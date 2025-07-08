// serpent/record.go
package serpent

import (
	"bytes"
	"errors"
	"io"
	"encoding/binary"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
)

const (
	// Record type for Serpent protocol when embedded in TLS record.
	// These are internal types, not actual TLS record types.
	RecordTypeHandshake     = 22 // Standard TLS handshake type
	RecordTypeApplicationData = 23 // Standard TLS application data type
	RecordTypeAlert         = 21 // Standard TLS alert type
	RecordTypeChangeCipherSpec = 20 // Standard TLS change cipher spec type

	// Maximum size for obfuscated record header to allow flexible search.
	MaxObfRecordHeaderSize = 256
)

// SerpentRecordHeaderMeta contains metadata for an obfuscated record header.
type SerpentRecordHeaderMeta struct {
	RecordType        uint8  // The actual TLS record type (e.g., handshake, application data)
	ActualPayloadLen  uint16 // The actual length of the TLS payload (excluding internal padding)
	Nonce             []byte // Random nonce for encryption (e.g., 3 bytes)
}

// BuildObfuscatedRecordHeader constructs a deeply obfuscated Serpent record header.
// It encrypts the true record type and length, embeds them into a random header,
// and adds HMAC for integrity.
func BuildObfuscatedRecordHeader(psc *SerpentPSC, typ uint8, actualPayloadLen int) ([]byte, error) {
	// Metadata to encrypt: RecordType (1B) + ActualPayloadLen (2B) + Nonce (3B) = 6 bytes
	meta := make([]byte, 6)
	meta[0] = typ
	binary.BigEndian.PutUint16(meta[1:3], uint16(actualPayloadLen))
	if _, err := io.ReadFull(rand.Reader, meta[3:6]); err != nil {
		return nil, err
	}

	// Encrypt metadata using AES-GCM
	encryptedMeta, err := EncryptWithAESGCM(psc.metaEncryptKey, meta, []byte(HMACLabelRecordHeader))
	if err != nil {
		return nil, err
	}

	// Determine variable header length (e.g., 64 to 256 bytes)
	headerLen64, err := GenerateRandomInt(64, MaxObfRecordHeaderSize+1) // Corrected: Handle error from GenerateRandomInt
	if err != nil {
		return nil, err
	}
	headerLen := int(headerLen64) // Cast to int

	if headerLen < len(encryptedMeta) + sha256.Size + 32 { // Ensure enough space for encrypted meta + HMAC + hmacData
		headerLen = len(encryptedMeta) + sha256.Size + 32 // Adjust if random was too small
	}
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(rand.Reader, header); err != nil {
		return nil, err
	}

	// Embed encrypted metadata into a pseudo-random location within the header.
	// For production: offset should be derived deterministically from `recordHeaderPRNGSeed`.
	// For demo, simplify by XORing at start.
	if len(header) < len(encryptedMeta) {
		return nil, errors.New("serpent: header buffer too short for encrypted metadata")
	}
	for i := 0; i < len(encryptedMeta); i++ {
		header[i] ^= encryptedMeta[i]
	}

	// Add HMAC for integrity over a fixed segment of the header (e.g., first 32 bytes after XOR)
	// This HMAC acts as a "magic number" + integrity check for header finding.
	hmacDataLen := 32 // Length of data to HMAC over
	if len(header) < hmacDataLen {
		hmacDataLen = len(header) // If header is too small, HMAC over whatever is available
	}
	hmacData := header[0:hmacDataLen] // HMAC over a consistent part of the pseudo-random header
	headerHMAC := psc.SerpentHMAC(HMACLabelRecordHeader, hmacData)
	
	if len(header) < hmacDataLen + sha256.Size { // Ensure header is big enough for HMAC and data
		return nil, errors.New("serpent: header too short for HMAC placement")
	}
	copy(header[len(header)-sha256.Size:], headerHMAC) // Place HMAC at the end

	return header, nil
}

// ParseObfuscatedRecordHeader attempts to parse an obfuscated record header from a byte slice.
// It uses a sliding window search for the HMAC and then attempts decryption.
// This function returns the parsed metadata and the length of the *consumed header*.
func ParseObfuscatedRecordHeader(psc *SerpentPSC, data []byte) (SerpentRecordHeaderMeta, int, error) {
	var meta SerpentRecordHeaderMeta
	var consumedHeaderLen int

	// Search for the HMAC from the end of possible header sizes, backwards.
	// This assumes HMAC is at the very end of the variable-length header.
	// Min encrypted meta (IV+6B+Tag) + min fixed data (32B for HMAC_data) + HMAC (32B)
	minHeaderSize := gcmNonceSize + 6 + gcmTagSize + 32 + sha256.Size 
	
	if len(data) < minHeaderSize {
		return meta, 0, errors.New("serpent: data too short for minimum header size check")
	}

	// Loop through potential header lengths from MaxObfRecordHeaderSize down to minHeaderSize
	// Ensure loop upper bound does not exceed actual data length
	for headerLen := len(data); headerLen >= minHeaderSize && headerLen >= 64; headerLen-- { // Also respect min header len from Build
		// Check for HMAC at the end of the current `headerLen` segment.
		potentialHeader := data[:headerLen]
		
		hmacDataLen := 32 // Expected length of data HMAC'd over
		if len(potentialHeader) < hmacDataLen + sha256.Size {
			continue // Not enough data for both hmacData and HMAC itself
		}

		testHMAC := potentialHeader[len(potentialHeader)-sha256.Size:]
		hmacData := potentialHeader[len(potentialHeader)-sha256.Size-hmacDataLen : len(potentialHeader)-sha256.Size] // Data to verify HMAC on

		expectedHMAC := psc.SerpentHMAC(HMACLabelRecordHeader, hmacData)
		
		if hmac.Equal(testHMAC, expectedHMAC) {
			// HMAC matches, now attempt to decrypt metadata.
			encryptedMetaLength := gcmNonceSize + 6 + gcmTagSize // IV + 6B meta + GCM Tag
			if len(potentialHeader) < encryptedMetaLength {
				continue // Header too short for encrypted meta
			}
			
			// Assume encrypted meta is NOT XORed but directly found here for simplicity of parsing.
			// The Build function's XORing is a simplification that's hard to reverse without prior knowledge.
			// In production, encrypted meta would be embedded directly at a PRNG-derived offset.
			encryptedMetaBytes := potentialHeader[0:encryptedMetaLength]
			
			decryptedMeta, decErr := DecryptWithAESGCM(psc.metaEncryptKey, encryptedMetaBytes, []byte(HMACLabelRecordHeader))
			
			if decErr == nil && len(decryptedMeta) >= 6 {
				meta.RecordType = decryptedMeta[0]
				meta.ActualPayloadLen = binary.BigEndian.Uint16(decryptedMeta[1:3])
				meta.Nonce = decryptedMeta[3:6]
				
				consumedHeaderLen = headerLen // This is the length of the header that was successfully parsed
				return meta, consumedHeaderLen, nil // Successfully parsed header
			}
		}
	}
	
	return meta, 0, errors.New("serpent: failed to parse obfuscated record header: no valid HMAC or decryption failed")
}


// BuildSerpentRecord constructs a complete Serpent record.
// It includes leading random padding, the obfuscated header, and the actual TLS payload
// with additional internal random padding to obscure its true length.
func BuildSerpentRecord(psc *SerpentPSC, recordType uint8, actualPayload []byte) ([]byte, error) {
	// 1. **Leading Random Padding:** Same mechanism as for ClientHello/ServerHello.
	paddingLen, err := RandomPaddingLength()
	if err != nil {
		return nil, err
	}
	paddingBytes := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, paddingBytes); err != nil { // For demo
		return nil, err
	}

	// Encrypt and embed padding length
	paddingMeta := make([]byte, 4)
	binary.BigEndian.PutUint16(paddingMeta[0:2], uint16(paddingLen))
	if _, err := io.ReadFull(rand.Reader, paddingMeta[2:4]); err != nil { return nil, err }
	encryptedPaddingMeta, err := EncryptWithAESGCM(psc.metaEncryptKey, paddingMeta, []byte(HMACLabelPseudoHeader))
	if err != nil { return nil, err }
	if len(paddingBytes) < len(encryptedPaddingMeta) { return nil, errors.New("serpent: padding too short") }
	for i := 0; i < len(encryptedPaddingMeta); i++ { paddingBytes[i] ^= encryptedPaddingMeta[i] }


	// 2. **Obfuscated Record Header:**
	obfHeader, err := BuildObfuscatedRecordHeader(psc, recordType, len(actualPayload))
	if err != nil {
		return nil, err
	}

	// 3. **Payload with Internal Padding:**
	// Add a random amount of internal padding to the actual payload.
	internalPadLen64, err := GenerateRandomInt(0, 2048) // Up to 2KB internal padding
	if err != nil {
		return nil, err
	}
	internalPadLen := int(internalPadLen64) // Cast to int

	internalPaddingBytes, err := GenerateRandomBytes(internalPadLen)
	if err != nil {
		return nil, err
	}
	obfuscatedPayload := append(actualPayload, internalPaddingBytes...)

	// 4. Combine all parts: padding + obfuscated header + obfuscated payload
	fullRecord := bytes.Join([][]byte{paddingBytes, obfHeader, obfuscatedPayload}, nil)

	return fullRecord, nil
}

// ParseSerpentRecord parses a complete Serpent record from an `io.Reader`.
// This function needs to be a robust state machine for production.
func ParseSerpentRecord(psc *SerpentPSC, r io.Reader) (uint8, []byte, error) {
	bufferedR := newPeekReader(r) // Use the peekReader for robust stream handling

	// Step 1: Find and consume leading padding.
	var actualPaddingLen int
	foundPadding := false
	searchWindowSize := 1024 // Max search for padding meta
	
	for readOffset := 0; readOffset < searchWindowSize; readOffset++ {
		requiredPeekLen := readOffset + (gcmNonceSize + 4 + gcmTagSize)
		if requiredPeekLen > cap(bufferedR.buf) { // Ensure we don't try to peek more than buffer capacity
			break
		}
		
		peekedBytes, err := bufferedR.Peek(requiredPeekLen)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break }
			return 0, nil, errors.New("serpent: peek error for record padding: " + err.Error())
		}
		
		if len(peekedBytes) < requiredPeekLen { // Still not enough data
			continue
		}

		// Assume encrypted padding meta is directly in the buffer (not XORed for parsing simplicity)
		testCiphertext := peekedBytes[readOffset : readOffset + (gcmNonceSize + 4 + gcmTagSize)]
		decryptedMeta, decErr := DecryptWithAESGCM(psc.metaEncryptKey, testCiphertext, []byte(HMACLabelPseudoHeader))
		
		if decErr == nil && len(decryptedMeta) >= 4 {
			possiblePaddingLen := int(binary.BigEndian.Uint16(decryptedMeta[0:2]))
			if possiblePaddingLen >= 64 && possiblePaddingLen < 1024 {
				actualPaddingLen = possiblePaddingLen
				foundPadding = true
				// Consume the bytes that contained the padding meta (and the bytes before it if any offset was found)
				if _, err := bufferedR.Read(make([]byte, readOffset + len(testCiphertext))); err != nil {
					return 0, nil, errors.New("serpent: failed to consume record padding meta: " + err.Error())
				}
				break
			}
		}
	}

	if !foundPadding {
		return 0, nil, errors.New("serpent: failed to find record padding length, attempting re-sync")
		// In production, would trigger silent drop and re-sync state.
	}

	// Consume the remaining padding bytes
	bytesToReadForPadding := actualPaddingLen - (gcmNonceSize + 4 + gcmTagSize)
	if bytesToReadForPadding > 0 {
		if _, err := bufferedR.Read(make([]byte, bytesToReadForPadding)); err != nil {
			return 0, nil, errors.New("serpent: failed to consume remaining record padding: " + err.Error())
		}
	}


	// Step 2: Find and Parse Obfuscated Record Header.
	var headerMeta SerpentRecordHeaderMeta
	var consumedHeaderLen int
	
	// Read a chunk that definitely contains the header (up to MaxObfRecordHeaderSize)
	peekedHeaderBytes, err := bufferedR.Peek(MaxObfRecordHeaderSize)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, nil, errors.New("serpent: peek error for record header: " + err.Error())
	}
	if len(peekedHeaderBytes) == 0 {
		return 0, nil, errors.New("serpent: no data available for record header")
	}

	// Call ParseObfuscatedRecordHeader to find and parse the header within the peeked bytes
	headerMeta, consumedHeaderLen, err = ParseObfuscatedRecordHeader(psc, peekedHeaderBytes)
	if err != nil {
		return 0, nil, errors.New("serpent: failed to find valid record header: " + err.Error())
		// In production, trigger silent drop and re-sync state.
	}
	
	// Consume the bytes corresponding to the parsed header from the buffered reader
	if _, err := bufferedR.Read(make([]byte, consumedHeaderLen)); err != nil {
		return 0, nil, errors.New("serpent: failed to consume record header bytes: " + err.Error())
	}
	
	// Step 3: Read and extract the actual TLS payload.
	// The `headerMeta.ActualPayloadLen` is the length of the *actual* TLS payload.
	// We need to read *at least* this many bytes, plus any internal random padding.
	// The `BuildSerpentRecord` adds up to 2048 bytes of internal padding.
	// So, we should attempt to read `headerMeta.ActualPayloadLen + MaxInternalPaddingAllowed`.
	maxInternalPaddingAllowed := 2048 // This should be a constant or derived from PSC
	
	// Pre-allocate buffer for the obfuscated payload, including potential padding.
	obfuscatedPayloadBytes := make([]byte, headerMeta.ActualPayloadLen + uint16(maxInternalPaddingAllowed))
	
	// Read up to the maximum possible obfuscated payload length.
	nPayload, err := io.ReadFull(bufferedR, obfuscatedPayloadBytes)
	if err != nil {
		// If ErrUnexpectedEOF, it means we got less than expected,
		// but we still need to check if we got at least the ActualPayloadLen.
		if err == io.ErrUnexpectedEOF && nPayload >= int(headerMeta.ActualPayloadLen) {
			// Enough data for actual payload, just not all expected padding.
		} else if err != io.ErrUnexpectedEOF {
			return 0, nil, errors.New("serpent: failed to read obfuscated payload: " + err.Error())
		}
	}
	obfuscatedPayloadBytes = obfuscatedPayloadBytes[:nPayload] // Adjust buffer to actual bytes read

	if len(obfuscatedPayloadBytes) < int(headerMeta.ActualPayloadLen) {
		return 0, nil, errors.New("serpent: obfuscated payload too short for actual TLS payload")
	}

	actualPayload := obfuscatedPayloadBytes[:headerMeta.ActualPayloadLen]

	return headerMeta.RecordType, actualPayload, nil
}

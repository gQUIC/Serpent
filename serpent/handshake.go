// serpent/handshake.go
package serpent

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// --- Outer ClientHello Construction ---

// BuildOuterClientHello constructs a deeply obfuscated Outer ClientHello.
// It wraps the actual (possibly ECH-encrypted) inner ClientHello with layers of random padding,
// pseudo-headers, and randomized TLS fields.
func BuildOuterClientHello(psc *SerpentPSC, innerClientHelloData []byte) ([]byte, error) {
	// 1. **Variable-Length Random Padding with Encrypted Length Hiding:**
	// The padding content is generated from a stream cipher keyed by PSC's paddingPRNGSeed.
	// The *actual length* of this padding is encrypted and placed in a pseudo-random,
	// but derivable, location within the padding.
	paddingLen, err := RandomPaddingLength()
	if err != nil {
		return nil, err
	}
	paddingBytes := make([]byte, paddingLen)

	// Create a deterministic PRNG for padding content based on PSC seed
	// In production, this PRNG needs to be robust (e.g., using AES-CTR with a fixed IV derived from seed)
	// For this example, let's use crypto/rand for padding content.
	if _, err := io.ReadFull(rand.Reader, paddingBytes); err != nil { // For demo, use crypto/rand for padding content
		return nil, err
	}

	// Encrypt the padding length (2 bytes) + random nonce (2 bytes) + HMAC on encrypted data
	// The meta-data is `[actual_padding_len (2B) | random_nonce (2B)]`
	paddingMeta := make([]byte, 4)
	binary.BigEndian.PutUint16(paddingMeta[0:2], uint16(paddingLen))
	if _, err := io.ReadFull(rand.Reader, paddingMeta[2:4]); err != nil {
		return nil, err
	}

	// Encrypt the metadata using AES-GCM
	encryptedPaddingMeta, err := EncryptWithAESGCM(psc.metaEncryptKey, paddingMeta, []byte(HMACLabelPseudoHeader))
	if err != nil {
		return nil, err
	}

	// Embed `encryptedPaddingMeta` at a pseudo-random offset within `paddingBytes`.
	// The offset calculation needs to be deterministic from PSC seeds on both ends.
	// For demo: Let's simplify by placing it at the start, XORed. Production needs better.
	if len(paddingBytes) < len(encryptedPaddingMeta) {
		return nil, errors.New("serpent: padding buffer too short to embed encrypted length meta")
	}
	for i := 0; i < len(encryptedPaddingMeta); i++ {
		paddingBytes[i] ^= encryptedPaddingMeta[i]
	}


	// 2. **Obfuscated TLS Record Header (pseudo-record header):**
	// This is a fake TLS record header that DPI might see. Its content is random,
	// but it contains a small, authenticated marker to signal "Serpent traffic".
	// Corrected: Handle error from GenerateRandomInt
	pseudoHeaderLen64, err := GenerateRandomInt(5, 64)
	if err != nil {
		return nil, err
	}
	pseudoHeaderLen := int(pseudoHeaderLen64) // Cast to int

	pseudoHeader := make([]byte, pseudoHeaderLen)
	if _, err := io.ReadFull(rand.Reader, pseudoHeader); err != nil {
		return nil, err
	}

	// Embed a small HMAC-SHA256 of a fixed label ("serpent-pseudo-hdr") at a pseudo-random offset
	// within the pseudo-header. This acts as a soft signal for Serpent.
	pseudoHeaderHMAC := psc.SerpentHMAC(HMACLabelPseudoHeader, []byte("start-marker"))
	if len(pseudoHeader) >= len(pseudoHeaderHMAC) {
		// Use a pseudo-random offset for HMAC placement derived from PRNGSeed
		// For demo, place at start
		copy(pseudoHeader[0:len(pseudoHeaderHMAC)], pseudoHeaderHMAC)
	}


	// 3. **Obfuscated ClientHello Body:**
	var ch clientHelloMsg
	ch.vers = uint16(SerpentMajorVersion<<8 | SerpentMinorVersion) // Fixed non-standard version for Serpent
	ch.random, err = GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	// Embed a PSC-derived HMAC fingerprint for robust identification.
	clientFp := psc.SerpentHMAC(HMACLabelClientHelloFingerprint, ch.random[8:]) // HMAC over part of random
	copy(ch.random[:len(clientFp)], clientFp) // Place fingerprint at beginning of random


	sessLen64, err := GenerateRandomInt(0, 33) // Session ID length 0-32
	if err != nil {
		return nil, err
	}
	ch.sessionId, err = GenerateRandomBytes(int(sessLen64)) // Cast to int
	if err != nil {
		return nil, err
	}

	suiteCount64, err := GenerateRandomInt(2, 16) // Cipher suites: random length and random values.
	if err != nil {
		return nil, err
	}
	suiteCount := int(suiteCount64) // Cast to int
	ch.cipherSuites = make([]uint16, suiteCount)
	for i := range ch.cipherSuites {
		val, err := GenerateRandomInt(0, 1<<16)
		if err != nil {
			return nil, err
		}
		ch.cipherSuites[i] = uint16(val)
	}

	compCount64, err := GenerateRandomInt(1, 8) // Compression methods: random length and random values.
	if err != nil {
		return nil, err
	}
	compCount := int(compCount64) // Cast to int
	ch.compressionMethods, err = GenerateRandomBytes(compCount)
	if err != nil {
		return nil, err
	}

	// Extensions: **Critical section for ECH and Grease**
	var extensions []Extension

	// ECH integration: The `innerClientHelloData` is the result of ECH encryption.
	// We wrap it in a Serpent-specific extension type, possibly adding more random padding.
	// `serpentECHExtType` is defined in serpent.go
	
	// Corrected: Handle error from GenerateRandomInt
	echExtPadLen64, err := GenerateRandomInt(32, 128)
	if err != nil {
		return nil, err
	}
	echExtPadLen := int(echExtPadLen64) // Cast to int

	echExtPayload := make([]byte, len(innerClientHelloData) + echExtPadLen) // Inner CH + random padding
	copy(echExtPayload, innerClientHelloData)
	if len(echExtPayload) > len(innerClientHelloData) { // Fill rest with random bytes
		if _, err := io.ReadFull(rand.Reader, echExtPayload[len(innerClientHelloData):]); err != nil {
			return nil, err
		}
	}
	// Corrected: Use ExtensionType directly
	extensions = append(extensions, Extension{Type: serpentECHExtType, Data: echExtPayload})

	// Add a large number of random "grease" extensions to obscure structure and make analysis harder.
	numGreaseExts64, err := GenerateRandomInt(10, 30) // 10 to 29 random grease extensions
	if err != nil {
		return nil, err
	}
	numGreaseExts := int(numGreaseExts64) // Cast to int

	for i := 0; i < numGreaseExts; i++ {
		extType64, err := GenerateRandomInt(0, 1<<16)
		if err != nil {
			return nil, err
		}
		extType := uint16(extType64) // Corrected: Cast to uint16

		// Avoid our specific ECH type or known critical TLS extension types (e.g., supported_versions, key_share)
		// Corrected: Compare ExtensionType with ExtensionType
		if ExtensionType(extType) == serpentECHExtType || extType == 0x002B || extType == 0x0033 { continue }
		
		extLen, err := RandomGreaseExtensionLength()
		if err != nil {
			return nil, err
		}
		extData, err := GenerateRandomBytes(extLen)
		if err != nil {
			return nil, err
		}
		// Corrected: Cast uint16 to ExtensionType
		extensions = append(extensions, Extension{Type: ExtensionType(extType), Data: extData})
	}
	ch.extensions = extensions

	// Marshal the obfuscated ClientHello message.
	obfCHBytes := ch.marshal()

	// Concatenate all parts: padding + pseudoHeader + obfuscated ClientHello
	fullSerpentCH := bytes.Join([][]byte{paddingBytes, pseudoHeader, obfCHBytes}, nil)

	return fullSerpentCH, nil
}

// --- Outer ClientHello Parsing ---

// ParseOuterClientHello parses a byte stream to identify and extract a Serpent Outer ClientHello.
// It performs robust parsing, HMAC verification, and metadata decryption.
// It takes an `io.Reader` as input for stream processing.
func ParseOuterClientHello(psc *SerpentPSC, r io.Reader) (*clientHelloMsg, []byte, error) {
	// A production-grade parser needs a robust state machine and buffering.
	// We'll simulate this with a `peekReader` or `bufio.Reader` internally.
	// This function assumes `r` is the underlying `net.Conn`.

	// Helper for buffered reading and peeking
	bufferedR := newPeekReader(r) // Custom peek-ahead buffer for stream parsing

	// 1. **Robust Padding Length Extraction & Consumption:**
	// Search for the encrypted padding length within a sliding window.
	// This is the most complex part of stream re-synchronization.
	var actualPaddingLen int
	foundPadding := false
	searchWindow := make([]byte, 1024) // Search up to 1KB for padding meta
	
	// Try to find the encrypted padding meta by trying to decrypt segments
	for readOffset := 0; readOffset < len(searchWindow); readOffset++ {
		// Calculate the required length to peek: current offset + encrypted meta size
		requiredPeekLen := readOffset + (gcmNonceSize + 4 + gcmTagSize)
		if requiredPeekLen > cap(bufferedR.buf) { // Avoid peeking beyond buffer capacity
			break
		}
		
		peekedBytes, err := bufferedR.Peek(requiredPeekLen)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break } // Not enough data yet
			return nil, nil, errors.New("serpent: peek error: " + err.Error())
		}
		
		if len(peekedBytes) < requiredPeekLen { // Still not enough data
			continue
		}

		// Attempt to decrypt a segment as encryptedPaddingMeta
		testCiphertext := peekedBytes[readOffset : readOffset + (gcmNonceSize + 4 + gcmTagSize)]
		decryptedMeta, decErr := DecryptWithAESGCM(psc.metaEncryptKey, testCiphertext, []byte(HMACLabelPseudoHeader))
		
		if decErr == nil && len(decryptedMeta) >= 4 {
			// Check nonce or other indicators if necessary
			possiblePaddingLen := int(binary.BigEndian.Uint16(decryptedMeta[0:2]))
			if possiblePaddingLen >= 64 && possiblePaddingLen < 1024 { // Validate against expected range
				actualPaddingLen = possiblePaddingLen
				foundPadding = true
				// Consume the actual bytes used for encrypted meta from the stream (which were XORed with padding)
				if _, err := bufferedR.Read(make([]byte, readOffset + len(testCiphertext))); err != nil {
					return nil, nil, errors.New("serpent: failed to consume padding meta: " + err.Error())
				}
				break
			}
		}
	}

	if !foundPadding {
		return nil, nil, errors.New("serpent: failed to find encrypted padding length in stream, attempting re-sync")
		// In production, would trigger silent drop and re-sync state.
	}

	// Consume the remaining padding bytes
	// Make sure we don't try to read negative bytes if actualPaddingLen was small
	bytesToReadForPadding := actualPaddingLen - (gcmNonceSize + 4 + gcmTagSize)
	if bytesToReadForPadding > 0 {
		if _, err := bufferedR.Read(make([]byte, bytesToReadForPadding)); err != nil {
			return nil, nil, errors.New("serpent: failed to consume remaining padding: " + err.Error())
		}
	}


	// 2. **Identify and Consume Obfuscated TLS Record Header (pseudo-header):**
	// Search for the pseudo-header HMAC within a window.
	var pseudoHeaderBytes []byte
	foundPseudoHeader := false
	pseudoHeaderHMACLen := sha256.Size // Corrected: Use sha256.Size

	// Search for the HMAC from possible pseudo header lengths
	for headerAttemptLen := 5; headerAttemptLen <= 64; headerAttemptLen++ {
		if headerAttemptLen < pseudoHeaderHMACLen { continue }
		
		// Peek enough bytes for the current header attempt
		peekedBytes, err := bufferedR.Peek(headerAttemptLen)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break }
			return nil, nil, errors.New("serpent: peek error for pseudo header: " + err.Error())
		}
		
		if len(peekedBytes) < headerAttemptLen { continue } // Not enough bytes peeked

		testHMAC := peekedBytes[0:pseudoHeaderHMACLen] // Assuming HMAC is at start for demo
		expectedHMAC := psc.SerpentHMAC(HMACLabelPseudoHeader, []byte("start-marker"))
		
		if hmac.Equal(testHMAC, expectedHMAC) {
			pseudoHeaderBytes = make([]byte, headerAttemptLen)
			if _, err := bufferedR.Read(pseudoHeaderBytes); err != nil {
				return nil, nil, errors.New("serpent: failed to consume pseudo header: " + err.Error())
			}
			foundPseudoHeader = true
			break
		}
	}
	
	if !foundPseudoHeader {
		return nil, nil, errors.New("serpent: failed to find pseudo header, attempting re-sync")
		// In production, trigger silent drop and re-sync
	}

	// 3. **Parse Obfuscated ClientHello Body:**
	// Read until a valid clientHelloMsg can be unmarshalled and fingerprint validated.
	// This requires careful state management to handle partial reads.
	var ch clientHelloMsg
	var innerCHData []byte

	// Read enough bytes to attempt unmarshalling a ClientHello.
	// This will loop, reading more if unmarshal fails or buffer is empty.
	for {
		// Peek enough bytes to attempt a ClientHello unmarshal
		// Assuming a reasonable max CH size for initial peek to avoid reading too much
		peekedCHBytes, err := bufferedR.Peek(4096) // Try with a large peek buffer (e.g., 4KB)
		if err != nil {
			if err == io.EOF { break } // No more data to peek
			if err == io.ErrUnexpectedEOF && len(peekedCHBytes) > 0 {
				// Allow trying to unmarshal with partial data if some is available
				// but mark that more data is expected if unmarshal fails
			} else {
				return nil, nil, errors.New("serpent: peek error for ClientHello: " + err.Error())
			}
		}
		
		if len(peekedCHBytes) == 0 {
			if err == io.EOF { break } // No more data
			return nil, nil, errors.New("serpent: insufficient data to parse ClientHello or EOF")
		}

		tempCH := clientHelloMsg{}
		if tempCH.unmarshal(peekedCHBytes) {
			// Check the ClientHello fingerprint
			if len(tempCH.random) >= sha256.Size { // Ensure random field is large enough for fingerprint
				clientFp := psc.SerpentHMAC(HMACLabelClientHelloFingerprint, tempCH.random[8:])
				if hmac.Equal(clientFp, tempCH.random[:len(clientFp)]) {
					// Valid ClientHello found! Consume the bytes and return.
					ch = tempCH
					
					// Determine the actual length of the unmarshaled CH.
					// This is difficult with the current `unmarshal` mock as it doesn't return consumed length.
					// A robust unmarshal would return `(bool, int)` where int is bytes consumed.
					// For now, we approximate by assuming unmarshal consumes `len(peekedCHBytes)` if successful.
					// In a real TLS implementation, `ch.marshal()` is predictable.
					consumedCHLen := len(ch.marshal()) // Re-marshal to get accurate size for consumption
					
					if _, err := bufferedR.Read(make([]byte, consumedCHLen)); err != nil {
						return nil, nil, errors.New("serpent: failed to consume ClientHello bytes: " + err.Error())
					}
					
					// Extract inner ECH payload from specific Serpent ECH extension
					for _, ext := range ch.extensions {
						// Corrected: Compare ExtensionType with ExtensionType
						if ext.Type == serpentECHExtType { // Our Serpent ECH type
							innerCHData = ext.Data // This is the encrypted inner CH + its random padding
							// In production, would then pass this to ECH decryption
							break
						}
					}
					
					return &ch, innerCHData, nil
				}
			}
		}
		
		// If unmarshal failed or fingerprint mismatch, consume some bytes and try again
		// This handles cases where we're out of sync or there's random data.
		// For robustness, consume a small random chunk or until next potential header.
		// Corrected: Handle error from GenerateRandomInt
		resyncReadLen64, err := GenerateRandomInt(1, 128)
		if err != nil {
			return nil, nil, errors.New("serpent: resync read length error: " + err.Error())
		}
		resyncReadLen := int(resyncReadLen64) // Cast to int
		
		if _, err := bufferedR.Read(make([]byte, resyncReadLen)); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break }
			return nil, nil, errors.New("serpent: failed to consume resync bytes: " + err.Error())
		}
	}

	return nil, nil, errors.New("serpent: failed to parse ClientHello after multiple attempts")
}

// --- Outer ServerHello Construction ---

// BuildOuterServerHello constructs a deeply obfuscated Outer ServerHello.
// Analogous to ClientHello construction, but for server-side.
func BuildOuterServerHello(psc *SerpentPSC, innerServerHelloData []byte) ([]byte, error) {
	// This would mirror `BuildOuterClientHello`'s logic, but with `HMACLabelServerHelloFingerprint`
	// and specific ServerHello fields and extensions.
	// For brevity, the full implementation is omitted but follows the same enhanced principles.
	
	// Mock ServerHello construction, assuming similar pattern to ClientHello
	// In a real implementation, this would be a distinct function.
	
	// 1. Padding
	paddingLen, err := RandomPaddingLength()
	if err != nil { return nil, err }
	paddingBytes := make([]byte, paddingLen)
	if _, err := io.ReadFull(rand.Reader, paddingBytes); err != nil { return nil, err }

	paddingMeta := make([]byte, 4)
	binary.BigEndian.PutUint16(paddingMeta[0:2], uint16(paddingLen))
	if _, err := io.ReadFull(rand.Reader, paddingMeta[2:4]); err != nil { return nil, err }
	encryptedPaddingMeta, err := EncryptWithAESGCM(psc.metaEncryptKey, paddingMeta, []byte(HMACLabelPseudoHeader))
	if err != nil { return nil, err }
	if len(paddingBytes) < len(encryptedPaddingMeta) { return nil, errors.New("serpent: padding too short") }
	for i := 0; i < len(encryptedPaddingMeta); i++ { paddingBytes[i] ^= encryptedPaddingMeta[i] }


	// 2. Pseudo Header
	pseudoHeaderLen64, err := GenerateRandomInt(5, 64)
	if err != nil { return nil, err }
	pseudoHeaderLen := int(pseudoHeaderLen64)
	pseudoHeader := make([]byte, pseudoHeaderLen)
	if _, err := io.ReadFull(rand.Reader, pseudoHeader); err != nil { return nil, err }

	pseudoHeaderHMAC := psc.SerpentHMAC(HMACLabelPseudoHeader, []byte("start-marker"))
	if len(pseudoHeader) >= len(pseudoHeaderHMAC) {
		copy(pseudoHeader[0:len(pseudoHeaderHMAC)], pseudoHeaderHMAC)
	}

	// 3. Obfuscated ServerHello Body
	var sh serverHelloMsg
	sh.vers = uint16(SerpentMajorVersion<<8 | SerpentMinorVersion)
	sh.random, err = GenerateRandomBytes(32)
	if err != nil { return nil, err }

	serverFp := psc.SerpentHMAC(HMACLabelServerHelloFingerprint, sh.random[8:])
	copy(sh.random[:len(serverFp)], serverFp)

	sessLen64, err := GenerateRandomInt(0, 33)
	if err != nil { return nil, err }
	sh.sessionId, err = GenerateRandomBytes(int(sessLen64))
	if err != nil { return nil, err }

	// Corrected: Handle error for GenerateRandomInt
	cipherSuiteVal, err := GenerateRandomInt(0, 1<<16)
	if err != nil { return nil, err }
	sh.cipherSuite = uint16(cipherSuiteVal) // Simplified, pick one random

	// Corrected: Handle error for GenerateRandomInt
	compressionMethodVal, err := GenerateRandomInt(0, 2)
	if err != nil { return nil, err }
	sh.compressionMethod = uint8(compressionMethodVal) // Simplified, pick one random

	var extensions []Extension
	// `serpentECHExtType` is defined in serpent.go
	echExtPadLen64, err := GenerateRandomInt(32, 128)
	if err != nil { return nil, err }
	echExtPadLen := int(echExtPadLen64)
	echExtPayload := make([]byte, len(innerServerHelloData) + echExtPadLen)
	copy(echExtPayload, innerServerHelloData)
	if len(echExtPayload) > len(innerServerHelloData) {
		if _, err := io.ReadFull(rand.Reader, echExtPayload[len(innerServerHelloData):]); err != nil { return nil, err }
	}
	// Corrected: Use ExtensionType directly
	extensions = append(extensions, Extension{Type: serpentECHExtType, Data: echExtPayload})

	numGreaseExts64, err := GenerateRandomInt(10, 30)
	if err != nil { return nil, err }
	numGreaseExts := int(numGreaseExts64)

	for i := 0; i < numGreaseExts; i++ {
		extType64, err := GenerateRandomInt(0, 1<<16)
		if err != nil { return nil, err }
		extType := uint16(extType64)
		// Corrected: Compare ExtensionType with ExtensionType
		if ExtensionType(extType) == serpentECHExtType || extType == 0x002B || extType == 0x0033 { continue }
		extLen, err := RandomGreaseExtensionLength()
		if err != nil { return nil, err }
		extData, err := GenerateRandomBytes(extLen)
		if err != nil { return nil, err }
		// Corrected: Cast uint16 to ExtensionType
		extensions = append(extensions, Extension{Type: ExtensionType(extType), Data: extData})
	}
	sh.extensions = extensions

	obfSHBytes := sh.marshal()
	fullSerpentSH := bytes.Join([][]byte{paddingBytes, pseudoHeader, obfSHBytes}, nil)

	return fullSerpentSH, nil
}

// --- Outer ServerHello Parsing ---

// ParseOuterServerHello parses a byte stream to identify and extract a Serpent Outer ServerHello.
// Analogous to ClientHello parsing, but for server-side.
func ParseOuterServerHello(psc *SerpentPSC, r io.Reader) (*serverHelloMsg, []byte, error) {
	bufferedR := newPeekReader(r)

	// 1. Padding parsing (same as ClientHello)
	var actualPaddingLen int
	foundPadding := false
	searchWindowSize := 1024
	
	for readOffset := 0; readOffset < searchWindowSize; readOffset++ {
		requiredPeekLen := readOffset + (gcmNonceSize + 4 + gcmTagSize)
		if requiredPeekLen > cap(bufferedR.buf) { break }
		
		peekedBytes, err := bufferedR.Peek(requiredPeekLen)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break }
			return nil, nil, errors.New("serpent: peek error for server hello padding: " + err.Error())
		}
		if len(peekedBytes) < requiredPeekLen { continue }

		testCiphertext := peekedBytes[readOffset : readOffset + (gcmNonceSize + 4 + gcmTagSize)]
		decryptedMeta, decErr := DecryptWithAESGCM(psc.metaEncryptKey, testCiphertext, []byte(HMACLabelPseudoHeader))
		
		if decErr == nil && len(decryptedMeta) >= 4 {
			possiblePaddingLen := int(binary.BigEndian.Uint16(decryptedMeta[0:2]))
			if possiblePaddingLen >= 64 && possiblePaddingLen < 1024 {
				actualPaddingLen = possiblePaddingLen
				foundPadding = true
				if _, err := bufferedR.Read(make([]byte, readOffset + len(testCiphertext))); err != nil {
					return nil, nil, errors.New("serpent: failed to consume server hello padding meta: " + err.Error())
				}
				break
			}
		}
	}

	if !foundPadding {
		return nil, nil, errors.New("serpent: failed to find encrypted server hello padding length")
	}

	bytesToReadForPadding := actualPaddingLen - (gcmNonceSize + 4 + gcmTagSize)
	if bytesToReadForPadding > 0 {
		if _, err := bufferedR.Read(make([]byte, bytesToReadForPadding)); err != nil {
			return nil, nil, errors.New("serpent: failed to consume remaining server hello padding: " + err.Error())
		}
	}

	// 2. Pseudo Header parsing (same as ClientHello)
	var pseudoHeaderBytes []byte
	foundPseudoHeader := false
	pseudoHeaderHMACLen := sha256.Size // Corrected: Use sha256.Size

	for headerAttemptLen := 5; headerAttemptLen <= 64; headerAttemptLen++ {
		if headerAttemptLen < pseudoHeaderHMACLen { continue }
		
		peekedBytes, err := bufferedR.Peek(headerAttemptLen)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break }
			return nil, nil, errors.New("serpent: peek error for server hello pseudo header: " + err.Error())
		}
		if len(peekedBytes) < headerAttemptLen { continue }

		testHMAC := peekedBytes[0:pseudoHeaderHMACLen]
		expectedHMAC := psc.SerpentHMAC(HMACLabelPseudoHeader, []byte("start-marker"))
		
		if hmac.Equal(testHMAC, expectedHMAC) {
			pseudoHeaderBytes = make([]byte, headerAttemptLen)
			if _, err := bufferedR.Read(pseudoHeaderBytes); err != nil {
				return nil, nil, errors.New("serpent: failed to consume server hello pseudo header: " + err.Error())
			}
			foundPseudoHeader = true
			break
		}
	}
	
	if !foundPseudoHeader {
		return nil, nil, errors.New("serpent: failed to find server hello pseudo header")
	}

	// 3. Parse Obfuscated ServerHello Body.
	var sh serverHelloMsg
	var innerSHData []byte

	for {
		peekedSHBytes, err := bufferedR.Peek(4096)
		if err != nil {
			if err == io.EOF { break }
			if err == io.ErrUnexpectedEOF && len(peekedSHBytes) > 0 {
				// Continue with partial data
			} else {
				return nil, nil, errors.New("serpent: peek error for ServerHello: " + err.Error())
			}
		}
		
		if len(peekedSHBytes) == 0 {
			if err == io.EOF { break }
			return nil, nil, errors.New("serpent: insufficient data to parse ServerHello or EOF")
		}

		tempSH := serverHelloMsg{}
		if tempSH.unmarshal(peekedSHBytes) {
			if len(tempSH.random) >= sha256.Size {
				serverFp := psc.SerpentHMAC(HMACLabelServerHelloFingerprint, tempSH.random[8:])
				if hmac.Equal(serverFp, tempSH.random[:len(serverFp)]) {
					sh = tempSH
					consumedSHLen := len(sh.marshal())
					if _, err := bufferedR.Read(make([]byte, consumedSHLen)); err != nil {
						return nil, nil, errors.New("serpent: failed to consume ServerHello bytes: " + err.Error())
					}
					
					for _, ext := range sh.extensions {
						// Corrected: Compare ExtensionType with ExtensionType
						if ext.Type == serpentECHExtType { // Our Serpent ECH type
							innerSHData = ext.Data
							break
						}
					}
					return &sh, innerSHData, nil
				}
			}
		}
		
		resyncReadLen64, err := GenerateRandomInt(1, 128)
		if err != nil { return nil, nil, errors.New("serpent: resync read length error: " + err.Error()) }
		resyncReadLen := int(resyncReadLen64)
		
		if _, err := bufferedR.Read(make([]byte, resyncReadLen)); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF { break }
			return nil, nil, errors.New("serpent: failed to consume resync bytes: " + err.Error())
		}
	}

	return nil, nil, errors.New("serpent: failed to parse ServerHello after multiple attempts")
}

// peekReader is a helper for stream parsing, allowing peeking into the stream.
// This simulates the capabilities of a bufio.Reader but for arbitrary peeking.
type peekReader struct {
	r   io.Reader
	buf []byte
	off int // Current read offset in buf
}

func newPeekReader(r io.Reader) *peekReader {
	return &peekReader{r: r, buf: make([]byte, 0, 4096)} // Start with 4KB capacity
}

// Peek returns the next n bytes without advancing the reader.
func (pr *peekReader) Peek(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("peekReader: negative count")
	}
	for len(pr.buf)-pr.off < n {
		// Need to read more data
		if pr.off > 0 && len(pr.buf) == cap(pr.buf) { // Buffer is full, but some data has been consumed, shift
			copy(pr.buf, pr.buf[pr.off:])
			pr.buf = pr.buf[:len(pr.buf)-pr.off]
			pr.off = 0
		}
		if len(pr.buf) == cap(pr.buf) { // Still full even after shifting, grow buffer
			newBuf := make([]byte, len(pr.buf), cap(pr.buf)*2)
			copy(newBuf, pr.buf)
			pr.buf = newBuf
		}
		
		// Read into remaining capacity
		nRead, err := pr.r.Read(pr.buf[len(pr.buf):cap(pr.buf)])
		pr.buf = pr.buf[:len(pr.buf)+nRead]
		if err != nil {
			if err == io.EOF && len(pr.buf)-pr.off >= n {
				return pr.buf[pr.off:pr.off+n], nil // Read enough before EOF
			}
			return nil, err
		}
	}
	return pr.buf[pr.off:pr.off+n], nil
}

// Read reads bytes from the reader, advancing the offset.
func (pr *peekReader) Read(p []byte) (n int, err error) {
	if len(pr.buf)-pr.off >= len(p) { // Enough bytes in buffer
		copy(p, pr.buf[pr.off:pr.off+len(p)])
		pr.off += len(p)
		return len(p), nil
	}
	// Not enough in buffer, drain buffer and then read directly
	nCopied := copy(p, pr.buf[pr.off:])
	pr.off = len(pr.buf) // Buffer is now empty from offset onwards
	
	nRead, err := pr.r.Read(p[nCopied:])
	return nCopied + nRead, err
}

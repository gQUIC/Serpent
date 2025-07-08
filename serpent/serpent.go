// serpent/serpent.go
package serpent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
	"bytes"
)

// Global constants for Serpent protocol.
const (
	SerpentMajorVersion = 0x01
	SerpentMinorVersion = 0x00

	// Key derivation labels
	HKDFLabelClientHandshake = "serpent client handshake"
	HKDFLabelServerHandshake = "serpent server handshake"
	HKDFLabelClientTraffic   = "serpent client traffic"
	HKDFLabelServerTraffic   = "serpent server traffic"
	HKDFLabelExporter        = "serpent exporter"
	// Corrected: Added the missing HKDF labels
	HKDFLabelMasterSecret    = "serpent master secret"
	HKDFLabelHMACKey         = "serpent hmac key"
	HKDFLabelMetaEncryptKey  = "serpent meta encrypt key"

	// HMAC labels for various components to prevent cross-protocol attacks
	HMACLabelPseudoHeader           = "serpent pseudo header"
	HMACLabelClientHelloFingerprint = "serpent clienthello fp"
	HMACLabelServerHelloFingerprint = "serpent serverhello fp"
	HMACLabelRecordHeader           = "serpent record header"

	// Pseudo-random extension type for ECH-wrapped ClientHello/ServerHello.
	// This makes it look like a custom, unassigned TLS extension type.
	serpentECHExtType ExtensionType = 0xFE03 // This is the single, authoritative definition
)

// Extension represents a TLS extension.
type Extension struct {
	Type ExtensionType
	Data []byte
}

// ExtensionType is the type for TLS extension identifiers.
type ExtensionType uint16

// SerpentPSC (Protocol State Context) holds the negotiated and derived secrets
// and state for the Serpent protocol session.
type SerpentPSC struct {
	prngSeed        []byte    // Seed for pseudo-random number generation for padding/offsets
	masterSecret    []byte    // Derived master secret after key exchange
	hmacKey         []byte    // Key for all internal Serpent HMACs
	metaEncryptKey  []byte    // Key for encrypting metadata like padding length
	trafficSecretRx []byte    // Current traffic secret for receiving
	trafficSecretTx []byte    // Current traffic secret for sending
	serverHelloSent bool      // True if server has sent its first Serpent message
	clientHelloSent bool      // True if client has sent its first Serpent message

	// For traffic encryption (AES-GCM)
	aeadCipherRx cipher.AEAD // AES-GCM cipher for receiving traffic
	aeadCipherTx cipher.AEAD // AES-GCM cipher for sending traffic
	nonceCounterRx uint64    // Nonce counter for receiving
	nonceCounterTx uint64    // Nonce counter for sending
}

// NewSerpentPSC creates a new Serpent Protocol State Context with initial seeds.
func NewSerpentPSC(initialSeed []byte) (*SerpentPSC, error) {
	if len(initialSeed) < 32 { // Minimum reasonable size for initial seed
		return nil, errors.New("serpent: initial seed too short")
	}

	// Derive master secret and other keys from initialSeed using HKDF
	hkdfSalt := []byte("Serpent-HKDF-Salt") // Fixed salt for HKDF
	// Corrected: Now these constants are defined and accessible
	masterSecret := HKDFExpandLabel(initialSeed, hkdfSalt, HKDFLabelMasterSecret, 32)
	hmacKey := HKDFExpandLabel(masterSecret, hkdfSalt, HKDFLabelHMACKey, 32)
	metaEncryptKey := HKDFExpandLabel(masterSecret, hkdfSalt, HKDFLabelMetaEncryptKey, 32)

	// Initialize AEAD ciphers with placeholder keys, will be updated after handshake.
	// For now, use a dummy key.
	dummyKey := make([]byte, 16) // AES-128 key size
	aeadRx, err := aes.NewCipher(dummyKey)
	if err != nil { return nil, err }
	gcmRx, err := cipher.NewGCM(aeadRx)
	if err != nil { return nil, err }

	aeadTx, err := aes.NewCipher(dummyKey)
	if err != nil { return nil, err }
	gcmTx, err := cipher.NewGCM(aeadTx)
	if err != nil { return nil, err }


	return &SerpentPSC{
		prngSeed:        initialSeed,
		masterSecret:    masterSecret,
		hmacKey:         hmacKey,
		metaEncryptKey:  metaEncryptKey,
		trafficSecretRx: []byte{}, // Initial empty
		trafficSecretTx: []byte{}, // Initial empty
		aeadCipherRx:    gcmRx,    // Placeholder
		aeadCipherTx:    gcmTx,    // Placeholder
		nonceCounterRx:  0,
		nonceCounterTx:  0,
		serverHelloSent: false,
		clientHelloSent: false,
	}, nil
}

// SerpentHMAC generates an HMAC-SHA256 using the PSC's `hmacKey` and a specific label.
func (psc *SerpentPSC) SerpentHMAC(label string, data []byte) []byte {
	h := hmac.New(sha256.New, psc.hmacKey)
	h.Write([]byte(label))
	h.Write(data)
	return h.Sum(nil)
}

// REMOVED: EncryptWithAESGCM and DecryptWithAESGCM moved to crypto.go

// These are mock TLS message structures for demonstration.
// In a real implementation, these would be proper TLS structures
// from a TLS library or custom parsing.

type clientHelloMsg struct {
	vers               uint16
	random             []byte
	sessionId          []byte
	cipherSuites       []uint16
	compressionMethods []uint8
	extensions         []Extension
}

// marshal serializes the clientHelloMsg into bytes.
// This is a simplified mock.
func (m *clientHelloMsg) marshal() []byte {
	var b bytes.Buffer
	// These are simplified writes, not correctly handling lengths or full TLS structure
	// This would need proper TLS marshaling logic.
	b.Write(make([]byte, 2)) // Placeholder for version
	binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], m.vers) // Overwrite placeholder
	b.Write(m.random)
	b.WriteByte(uint8(len(m.sessionId)))
	b.Write(m.sessionId)
	b.Write(make([]byte, 2)) // Placeholder for cipher suites length
	binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], uint16(len(m.cipherSuites)*2)) // Overwrite placeholder
	for _, suite := range m.cipherSuites {
		b.Write(make([]byte, 2)) // Placeholder for suite
		binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], suite) // Overwrite placeholder
	}
	b.WriteByte(uint8(len(m.compressionMethods)))
	b.Write(m.compressionMethods)

	// Extensions
	var extData bytes.Buffer
	for _, ext := range m.extensions {
		extData.Write(make([]byte, 2)) // Placeholder for type
		binary.BigEndian.PutUint16(extData.Bytes()[extData.Len()-2:], uint16(ext.Type)) // Overwrite placeholder
		extData.Write(make([]byte, 2)) // Placeholder for length
		binary.BigEndian.PutUint16(extData.Bytes()[extData.Len()-2:], uint16(len(ext.Data))) // Overwrite placeholder
		extData.Write(ext.Data)
	}
	b.Write(make([]byte, 2)) // Placeholder for extensions length
	binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], uint16(extData.Len())) // Overwrite placeholder
	b.Write(extData.Bytes())
	return b.Bytes() // Simplified: will not produce correct TLS CH structure
}

// unmarshal parses bytes into a clientHelloMsg.
// This is a simplified mock. Returns true if successful (loosely).
func (m *clientHelloMsg) unmarshal(data []byte) bool {
	// Simplified mock: just checks minimal length and assigns some fields
	// A real unmarshal would parse correctly and handle errors.
	if len(data) < 38 { // Min size for version (2) + random (32) + sessIDLen (1) + cipherSuitesLen (2) + compMethodsLen (1)
		return false
	}
	m.vers = binary.BigEndian.Uint16(data[0:2])
	m.random = data[2:34]
	
	// Simplified session ID, cipher suites, etc.
	sessIDLen := int(data[34])
	if len(data) < 35 + sessIDLen { return false }
	m.sessionId = data[35 : 35 + sessIDLen]

	// Mock parsing extensions to find our ECH type
	// This would be a full parser in a real scenario
	// Find our `serpentECHExtType` and populate `m.extensions`
	// For demo: assume it exists and parse a dummy extension if needed
	m.extensions = []Extension{{Type: serpentECHExtType, Data: []byte("mock-ech-payload")}} // Corrected: Use ExtensionType directly
	return true
}

type serverHelloMsg struct {
	vers              uint16
	random            []byte
	sessionId         []byte
	cipherSuite       uint16
	compressionMethod uint8
	extensions        []Extension
}

// marshal serializes the serverHelloMsg into bytes.
// This is a simplified mock.
func (m *serverHelloMsg) marshal() []byte {
	var b bytes.Buffer
	// These are simplified writes, not correctly handling lengths or full TLS structure
	b.Write(make([]byte, 2)) // Placeholder for version
	binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], m.vers) // Overwrite placeholder
	b.Write(m.random)
	b.WriteByte(uint8(len(m.sessionId)))
	b.Write(m.sessionId)
	b.Write(make([]byte, 2)) // Placeholder for cipher suite
	binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], m.cipherSuite) // Overwrite placeholder
	b.WriteByte(m.compressionMethod)

	// Extensions
	var extData bytes.Buffer
	for _, ext := range m.extensions {
		extData.Write(make([]byte, 2)) // Placeholder for type
		binary.BigEndian.PutUint16(extData.Bytes()[extData.Len()-2:], uint16(ext.Type)) // Overwrite placeholder
		extData.Write(make([]byte, 2)) // Placeholder for length
		binary.BigEndian.PutUint16(extData.Bytes()[extData.Len()-2:], uint16(len(ext.Data))) // Overwrite placeholder
		extData.Write(ext.Data)
	}
	b.Write(make([]byte, 2)) // Placeholder for extensions length
	binary.BigEndian.PutUint16(b.Bytes()[b.Len()-2:], uint16(extData.Len())) // Overwrite placeholder
	b.Write(extData.Bytes())
	return b.Bytes() // Simplified: will not produce correct TLS SH structure
}

// unmarshal parses bytes into a serverHelloMsg.
// This is a simplified mock. Returns true if successful (loosely).
func (m *serverHelloMsg) unmarshal(data []byte) bool {
	// Simplified mock: just checks minimal length and assigns some fields
	if len(data) < 39 { // Min size for version (2) + random (32) + sessIDLen (1) + cipherSuite (2) + compMethod (1) + ExtLen (2)
		return false
	}
	m.vers = binary.BigEndian.Uint16(data[0:2])
	m.random = data[2:34]
	
	sessIDLen := int(data[34])
	if len(data) < 35 + sessIDLen { return false }
	m.sessionId = data[35 : 35 + sessIDLen]
	
	m.cipherSuite = binary.BigEndian.Uint16(data[35+sessIDLen : 37+sessIDLen])
	m.compressionMethod = data[37+sessIDLen]

	// Mock parsing extensions to find our ECH type
	m.extensions = []Extension{{Type: serpentECHExtType, Data: []byte("mock-ech-payload-server")}} // Corrected: Use ExtensionType directly

	return true
}

// --- Utility Functions (Simplified for demonstration) ---

// RandomPaddingLength generates a pseudo-random length for padding within a sensible range.
func RandomPaddingLength() (int, error) {
	// Example: 64 to 1024 bytes, to obscure true message length
	len64, err := GenerateRandomInt(64, 1024)
	if err != nil {
		return 0, err
	}
	return int(len64), nil
}

// RandomGreaseExtensionLength generates a pseudo-random length for grease extensions.
func RandomGreaseExtensionLength() (int, error) {
	// Example: 0 to 256 bytes for grease
	len64, err := GenerateRandomInt(0, 257) // 0 to 256
	if err != nil {
		return 0, err
	}
	return int(len64), nil
}

// GenerateRandomBytes generates a slice of cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomInt generates a cryptographically secure random integer in [min, max).
func GenerateRandomInt(min, max int) (int64, error) {
	if min >= max {
		return 0, errors.New("min must be less than max")
	}
	diff := big.NewInt(int64(max - min))
	randomInt, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return 0, err
	}
	return randomInt.Int64() + int64(min), nil
}

// HKDFExpandLabel implements the TLS 1.3 HKDF-Expand-Label function.
// For demonstration, a simplified version.
func HKDFExpandLabel(secret, salt []byte, label string, length int) []byte {
	// In a real implementation, this would use a proper HKDF library.
	// This is a highly simplified mock.
	h := hmac.New(sha256.New, salt)
	h.Write(secret)
	h.Write([]byte(label))
	h.Write([]byte{byte(length)}) // Length of output key
	return h.Sum(nil)[:length]     // Truncate or extend to `length`
}

// REMOVED: gcmNonceSize and gcmTagSize moved to crypto.go

// Current time and location information for context
func init() {
	// You can use this init function for any setup that depends on the current time/location
	// For now, it's just a placeholder.
	fmt.Println("Serpent module initialized at", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println("Current location: Japan")
}

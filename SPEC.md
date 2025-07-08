## Serpent Protocol: ECH-Based Deep Masquerading TLS Protocol (Serpent/1.1)

### Abstract

The Serpent Protocol aims to evade network censorship and Deep Packet Inspection (DPI) by **deeply masquerading** the TLS handshake and all subsequent record messages. This protocol leverages Encrypted ClientHello (ECH) to encrypt the ClientHello message, hiding it within seemingly random data. Furthermore, all TLS handshake messages (including ClientHello and ServerHello) and all subsequent TLS record headers are dynamically reconstructed and randomized. Additionally, each Serpent record includes a leading, variable-length random padding field, whose length information is itself obfuscated, making the entire traffic flow appear as irregular encrypted bytes to external observers, indistinguishable from regular TLS traffic.

This specification defines the structure, message formats, and key processes of the Serpent Protocol to enable interoperability between clients and servers.

-----

### 1\. Introduction

The Serpent Protocol is designed to circumvent network censorship and Deep Packet Inspection (DPI) by employing **deep masquerading** techniques on TLS traffic. It achieves this by utilizing the Encrypted ClientHello (ECH) mechanism to encrypt and conceal the genuine ClientHello message within a facade of random data. Beyond ECH, Serpent extends its obfuscation to all TLS handshake messages (ClientHello and ServerHello) and subsequent TLS record headers, dynamically reconstructing and randomizing their visible fields. Each Serpent record further incorporates a leading, variable-length random padding, whose length information is also obfuscated. This multi-layered approach ensures that the entire traffic stream appears as unpredictable encrypted bytes, effectively concealing its identity as standard TLS traffic from external observation.

This document specifies the architecture, message formats, and operational procedures of the Serpent Protocol to facilitate interoperable implementations by clients and servers.

-----

### 2\. Terminology

The following terms are used throughout this document:

  * **Serpent Client:** A client entity that implements the Serpent Protocol.
  * **Serpent Server:** A server entity that implements the Serpent Protocol.
  * **Outer ClientHello:** As defined by the ECH RFC, the unencrypted external ClientHello message in ECH.
  * **Inner ClientHello:** As defined by the ECH RFC, the real ClientHello message encrypted within ECH.
  * **Outer ServerHello:** As defined by the Serpent Protocol, the external randomized masquerading ServerHello message.
  * **Inner ServerHello:** The standard TLS-defined ServerHello message, which will be concealed by the Serpent Protocol.
  * **Serpent Handshake:** The masquerading and negotiation process performed by the Serpent Protocol during the TLS handshake phase.
  * **Serpent Record:** The masquerading and transmission unit performed by the Serpent Protocol at the TLS record layer.
  * **Pre-Shared Context (PSC):** Information shared out-of-band between the Serpent Client and Server, containing protocol version, keys, ECH configuration, etc., used for identifying and de-obfuscating Serpent traffic.

-----

### 3\. Serpent Protocol Overview

The Serpent Protocol employs the following key mechanisms for deep masquerading:

  * **ClientHello Deep Masquerading:** The **Outer ClientHello** sent by the Serpent Client is thoroughly randomized. All its visible fields (TLS version, length, Session ID, Cipher Suites, and Extensions) are populated with seemingly random data. The true ClientHello (**Inner ClientHello**) is encrypted via ECH and hidden within this randomized Outer ClientHello.
  * **ServerHello Deep Masquerading:** The **Outer ServerHello** sent by the Serpent Server is also thoroughly randomized. Its TLS version, length, Session ID, Cipher Suites, and Extensions fields are similarly filled with seemingly random data. The true ServerHello (**Inner ServerHello**) is encrypted and hidden within this randomized Outer ServerHello.
  * **Serpent Handshake Identification:** Serpent Servers and Clients identify and validate a Serpent connection by parsing specific metadata within the Outer ClientHello or Outer ServerHello, which is encoded in a manner known only through the **Pre-Shared Context (PSC)**.
  * **TLS Record Header Masquerading:** All subsequent TLS records (Handshake, Alert, Application Data, Change Cipher Spec) have their headers (Type, Version, Length) dynamically reconstructed and randomized. The actual record type and length information are encoded and hidden within the masqueraded record header or its payload.
  * **Leading Random Padding:** Each Serpent record begins with a variable-length random padding. The length information of this padding is itself hidden and obfuscated, making the starting bytes of the entire record unpredictable.
  * **In-Record Padding and Obfuscation:** To further blur traffic characteristics, the Serpent Protocol performs random data padding within the TLS record Payload and may apply additional layers of obfuscation to the Payload itself.

-----

### 4\. Protocol Version

This specification defines the updated version of the Serpent Protocol: **Serpent/1.1**.

-----

### 5\. Pre-Shared Context (PSC)

The Serpent Client and Server **MUST** establish a **Pre-Shared Context (PSC)** out-of-band. The PSC **SHOULD** contain at least the following information:

  * **Serpent-Version:** The current Serpent Protocol version in use, e.g., "Serpent/1.1".
  * **Session-Key:** A cryptographically secure shared key used for:
      * Encoding/decoding hidden metadata in **Outer ClientHello** and **Outer ServerHello**.
      * Encoding/decoding the leading padding length and hidden metadata in Serpent record headers.
      * Keying additional obfuscation for the application layer Payload.
  * **ECH-Config:** The server's ECH public key configuration (for the client) or the server's ECH private key (for the server). This includes ECH-related parameters such as `HpkeKemId`, `HpkeKdfId`, `HpkeAeadId`.
  * **Obfuscation-Algorithms-Version:** An integer or string indicating the version of the ClientHello/ServerHello masquerading algorithms, record header obfuscation algorithm, and leading padding length encoding algorithm currently in use. This allows for future upgrades of obfuscation methods.

The PSC **MUST** be distributed securely, as its confidentiality is paramount to the stealth of the Serpent Protocol.

-----

### 6\. Serpent Handshake Process

The Serpent handshake is based on the TLS 1.3 handshake process, with the following modifications:

#### 6.1. Client Sending Outer ClientHello

The Serpent Client constructs an **Outer ClientHello** message whose structure and field values are deeply masqueraded:

  * **Leading Random Padding:** At the very beginning of the masqueraded ClientHello, a random length padding is added.

      * **Padding Length Encoding:** The actual length of the padding (e.g., 0-255 bytes) **MUST** be encoded in a covert manner derived from the **PSC.Session-Key**, either within specific bit patterns inside the padding itself or within the first few pseudo-random bytes of the Outer ClientHello immediately following the padding. The decoding party **MUST** use the PSC to identify and parse this length.
      * **Padding Content:** The padding content **MUST** consist of cryptographically secure random bytes.

  * **Outer ClientHello Structure Masquerading:**

    ```
    struct {
        uint8  major_version;           // Random value
        uint8  minor_version;           // Random value
        uint16 pseudo_record_type;      // Random value
        uint16 pseudo_record_length;    // Random value (SerpentClientHelloLength,
                                        // includes ECH and internal padding)
        // Actual ClientHello masquerading begins (ECH outer structure)
        uint16 client_hello_tls_version; // Random value (e.g., 0xXXXX)
        opaque random[32];               // Random bytes, embedding PSC identification fingerprint
        opaque session_id<0..32>;        // Random padding (random length)
        CipherSuite cipher_suites<2..2^16-2>; // Random padding (random length)
        opaque legacy_compression_methods<1..2^8-1>; // Random padding (random length)
        Extension extensions<0..2^16-1>; // Contains ECH extension, with extensive random padding
    } SerpentClientHello;
    ```

  * **Field Value Masquerading Details:**

      * `major_version`, `minor_version`, `pseudo_record_type`, `pseudo_record_length`: These fields **SHOULD** be filled with entirely random bytes. `pseudo_record_length` **SHOULD** be a random value greater than or equal to the actual **SerpentClientHello** byte length (including the ECH portion and internal padding). The actual message length information **MUST** be encoded via a PSC-known byte pattern or embedded metadata.
      * `client_hello_tls_version`: A non-standard TLS version number **SHOULD** be randomly chosen, e.g., `0x5C3F`.
      * `random`: 32 random bytes. The Serpent Client **MAY** embed a small HMAC or a specific bit pattern derived from **PSC.Session-Key** within these bytes as a quick identification fingerprint for Serpent traffic.
      * `session_id`, `cipher_suites`, `legacy_compression_methods`: These fields **SHOULD** be filled with random bytes. Their lengths **SHOULD** also be random to avoid any length patterns.
      * `extensions`: **MUST** contain a standard ECH ClientHello (`outer_ch_encrypted_ech`) extension, whose value is the **Inner ClientHello** encrypted using **PSC.ECH-Config**. In addition to the ECH extension, a significant amount of random padding extensions (Grease extensions) and/or random byte padding **SHOULD** be added to further obscure the structure.

#### 6.2. Server Parsing Outer ClientHello

Upon receiving the first byte stream of a connection, the Serpent Server **SHOULD** perform the following steps:

  * **Leading Padding Identification and Removal:** The server **MUST** first use the algorithms defined in **PSC.Session-Key** and **PSC.Obfuscation-Algorithms-Version** to parse the length of the leading padding from the initial bytes of the stream or via pattern matching, and then skip the corresponding padding bytes.
  * **Serpent ClientHello Identification and De-obfuscation:** Once the leading padding is removed, the server **MUST** attempt to extract hidden metadata indicating a Serpent ClientHello from a predetermined location in the remaining byte stream or via pattern matching, using algorithms defined in **PSC.Session-Key** and **PSC.Obfuscation-Algorithms-Version**. If identification fails, the server **SHOULD** fall back to processing a standard TLS ClientHello.
  * **De-obfuscating Outer ClientHello:** Once confirmed as a Serpent ClientHello, the server **MUST** parse the true length of the Outer ClientHello and the contained ECH extension according to the algorithms defined in **PSC.Obfuscation-Algorithms-Version**.
  * **ECH Decryption:** The server **MUST** decrypt the ECH extension using the private key in **PSC.ECH-Config** to obtain the **Inner ClientHello**.
  * **TLS 1.3 Handshake Continuation:** Once the **Inner ClientHello** is obtained, the server **MUST** proceed with the standard TLS 1.3 handshake process, including key negotiation, certificate validation, etc.

#### 6.3. Server Sending Outer ServerHello

After completing the **Inner ClientHello** processing and generating the **Inner ServerHello**, the Serpent Server constructs an **Outer ServerHello** message whose structure and field values are deeply masqueraded:

  * **Leading Random Padding:** At the very beginning of the masqueraded ServerHello, a random length padding is added. The padding length encoding method is the same as for the client's ClientHello, determined by the PSC.

  * **Outer ServerHello Structure Masquerading:**

    ```
    struct {
        uint8  major_version;           // Random value
        uint8  minor_version;           // Random value
        uint16 pseudo_record_type;      // Random value
        uint16 pseudo_record_length;    // Random value (SerpentServerHelloLength,
                                        // includes Inner ServerHello and internal padding)
        // Actual ServerHello masquerading begins
        uint16 server_hello_tls_version; // Random value (e.g., 0xXXXX)
        opaque random[32];               // Random bytes, embedding PSC identification fingerprint
        opaque session_id<0..32>;        // Random padding (random length)
        CipherSuite cipher_suite;        // Random padding
        opaque compression_method;       // Random padding
        Extension extensions<0..2^16-1>; // Contains Inner ServerHello, with extensive random padding
    } SerpentServerHello;
    ```

  * **Field Value Masquerading Details:**

      * `major_version`, `minor_version`, `pseudo_record_type`, `pseudo_record_length`: Same as ClientHello masquerading.
      * `server_hello_tls_version`: A non-standard TLS version number **SHOULD** be randomly chosen, e.g., `0x5C3F`.
      * `random`: 32 random bytes. The Serpent Server **MAY** embed a small HMAC or a specific bit pattern derived from **PSC.Session-Key** within these bytes as a Serpent traffic identification fingerprint.
      * `session_id`, `cipher_suite`, `compression_method`: These fields **SHOULD** be filled with random bytes. Their lengths **SHOULD** also be random to avoid any length patterns.
      * `extensions`: **MUST** contain the encrypted or obfuscated **Inner ServerHello**. The Inner ServerHello **MAY** be the value of a custom Serpent extension, or it **MAY** be fragmented and embedded into multiple randomly padded extensions. Similarly, a significant amount of random padding extensions and/or random byte padding **SHOULD** be added.

#### 6.4. Client Parsing Outer ServerHello

  * **Leading Padding Identification and Removal:** Similar to the server parsing ClientHello, the client **MUST** first remove the leading padding.
  * **Serpent ServerHello Identification and De-obfuscation:** The client **MUST** use the PSC to identify and de-obfuscate the **Outer ServerHello**. This includes extracting hidden metadata (e.g., HMAC, length information) from the masqueraded fields.
  * **Extracting Inner ServerHello:** The client **MUST** extract the encrypted or obfuscated **Inner ServerHello** from the masqueraded Outer ServerHello and perform necessary decryption/de-obfuscation.
  * **TLS 1.3 Handshake Continuation:** Once the **Inner ServerHello** is obtained, the client **MUST** proceed with the standard TLS 1.3 handshake process, including certificate validation, key derivation, etc.

-----

### 7\. Serpent Record Protocol

Once the TLS handshake is complete, all subsequent TLS records (encrypted handshake messages, application data, alerts, Change Cipher Spec) **MUST** be transmitted via the Serpent record protocol.

#### 7.1. Serpent Record Structure

The external structure of a Serpent record will be thoroughly randomized and no longer follow the standard `Type (1) | Version (2) | Length (2)` format.

  * **Leading Random Padding:**

      * **Padding Length Encoding:** At the very beginning of each Serpent record, there **MUST** be a leading padding. The length of this padding (e.g., 0-255 bytes) **MUST** be encoded in a covert manner derived from **PSC.Session-Key**, either within specific bit patterns inside the padding itself or within a few pseudo-random bytes of the obfuscated record header immediately following the padding. The decoding party **MUST** use the PSC to identify and parse this length.
      * **Padding Content:** The padding content **MUST** consist of cryptographically secure random bytes.

  * **Obfuscated Record Header:**

    ```
    struct {
        opaque random_bytes[PseudoHeaderLength]; // Pseudo-random bytes, random length (e.g., 5-64 bytes)
        // Hidden metadata (encoded via PSC.Session-Key)
        // - Actual record type (SerpentRecordType)
        // - Actual Payload length (ActualPayloadLength)
        // - Checksum/MAC (optional)
    } ObfuscatedRecordHeader;
    ```

      * `PseudoHeaderLength`: A random value, e.g., between 5 and 64 bytes.
      * **Hidden Metadata:** The actual record type and Payload length information **MUST** be encrypted using **PSC.Session-Key** and then scattered and hidden within the `random_bytes`. For example, they **MAY** be encoded as bit flips in a specific byte sequence or as part of the HMAC input.

  * **Obfuscated Payload:**

    ```
    struct {
        opaque actual_tls_payload<0..2^14-1>; // Actual TLS encrypted Payload (max 16KB)
        opaque internal_padding[InternalPaddingLength]; // Internal random padding bytes
    } ObfuscatedPayload;
    ```

      * `InternalPaddingLength`: To make the total length of the Serpent Record unpredictable, `InternalPaddingLength` **SHOULD** be calculated to make the `ObfuscatedPayload` reach a pseudo-random total length. `InternalPaddingLength` **MUST** be filled with cryptographically secure random numbers.

#### 7.2. Client/Server Sending Serpent Records

1.  **Obtain Encrypted TLS Payload:** Retrieve the encrypted TLS record Payload from the TLS layer (e.g., encrypted Application Data).
2.  **Construct Obfuscated Payload:** Combine the encrypted TLS Payload with random internal padding data to form the **ObfuscatedPayload**. The internal padding length **MUST** be calculated by an algorithm defined by **PSC.Obfuscation-Algorithms-Version** to ensure total length randomness.
3.  **Construct Obfuscated Record Header:** Generate random bytes for the **ObfuscatedRecordHeader**, and encode and embed metadata such as `SerpentRecordType` and `ActualPayloadLength` into the **ObfuscatedRecordHeader** using **PSC.Session-Key**.
4.  **Construct Leading Random Padding:** Generate random padding data. Its length information **MUST** be derived from **PSC.Session-Key** and covertly encoded within the padding itself or the immediately following obfuscated record header.
5.  **Assemble and Send:** Concatenate the leading random padding, **ObfuscatedRecordHeader**, and **ObfuscatedPayload** to form a complete Serpent Record, and send it directly over the underlying TCP/UDP connection.

#### 7.3. Client/Server Receiving Serpent Records

1.  **Read Raw Byte Stream:** The receiver continuously reads the raw byte stream from the underlying network connection.
2.  **Leading Padding Identification and Removal:** The receiver **MUST** first use the algorithms defined in **PSC.Session-Key** and **PSC.Obfuscation-Algorithms-Version** to parse the length of the leading padding from the initial bytes of the stream or via pattern matching, and then skip the corresponding padding bytes.
3.  **Record Boundary Identification and De-obfuscation:** Once the leading padding is removed, the receiver **MUST** attempt to identify the potential **ObfuscatedRecordHeader** from the remaining byte stream using algorithms defined in **PSC.Session-Key** and **PSC.Obfuscation-Algorithms-Version**, through sliding windows, pattern matching, or heuristic methods.
4.  Once a potential **ObfuscatedRecordHeader** is identified, the receiver **MUST** attempt to decode the hidden `ActualPayloadLength` and `SerpentRecordType` using **PSC.Session-Key**. If decoding is successful and a checksum matches (if implemented), it is considered that the start of a Serpent record has been found.
5.  **Read ObfuscatedPayload:** Based on the decoded `ActualPayloadLength`, read the corresponding length of the **ObfuscatedPayload**.
6.  **Extract Original TLS Payload:** Remove the internal padding data from the **ObfuscatedPayload** to obtain the original TLS encrypted Payload.
7.  **Deliver to TLS Layer:** Deliver the extracted original TLS encrypted Payload to the TLS layer for decryption and further processing.

-----

### 8\. Error Handling and Recovery

Due to the deep masquerading nature of the Serpent Protocol, any byte errors or synchronization issues may render messages unparseable.

  * **PSC Checksum/MAC:** All hidden metadata encoding **SHOULD** include a cryptographically secure checksum or Message Authentication Code (MAC) derived from **PSC.Session-Key** to verify data integrity and authenticity.
  * **Resynchronization Mechanisms:** When parsing errors occur, clients and servers **SHOULD** attempt to resynchronize. This **MAY** include:
      * Discarding currently unparseable bytes and attempting to re-identify the Serpent record header (including leading padding) in subsequent byte streams.
      * In extreme cases, a forced re-initiation of the Serpent handshake **MAY** be performed.
  * **Silent Failure:** To avoid being identified by censorship devices, the Serpent Protocol **SHOULD** silently fail upon parsing errors or retry without compromising stealth. Avoid sending identifiable error messages.

-----

### 9\. Security Considerations

  * **PSC Confidentiality:** The confidentiality of the **Pre-Shared Context (PSC)** is paramount. If the PSC is compromised, Serpent traffic may become identifiable.
  * **Randomness Quality:** All random numbers used for masquerading and padding **MUST** be cryptographically secure. Weaknesses in the Pseudo-Random Number Generator (PRNG) can lead to exposure of traffic patterns.
  * **ECH Security:** The stealth of the Serpent Protocol relies heavily on the security of ECH. Any weaknesses in ECH itself will directly impact the Serpent Protocol.
  * **Padding Attacks:** While padding aims to increase stealth, if padding length selection exhibits bias or predictability, it **MAY** lead to side-channel attacks. Uniformly distributed random padding lengths **SHOULD** be used.
  * **Traffic Analysis:** Even if individual messages are masqueraded, long-term traffic statistical analysis (e.g., connection duration, total bytes, connection establishment frequency) can still reveal anomalies. The Serpent Protocol **SHOULD** encourage the application layer to introduce random delays and traffic patterns to further counter such analysis.

-----

### 10\. Compatibility and Deployment

Implementations of the Serpent Protocol require deep modifications to standard `crypto/tls` libraries, meaning it **CANNOT** directly interoperate with standard TLS clients or servers. It requires a dedicated Serpent Client and Serpent Server to function.

-----

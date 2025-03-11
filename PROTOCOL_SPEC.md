# PQC Protocol Specification

**Version:** 1.0  
**Last Updated:** March 11, 2025  
**Status:** Draft

## 1. Introduction

The Post-Quantum Cryptography (PQC) Protocol is a secure communication protocol designed to resist attacks from both classical and quantum computers. It implements NIST-standardized post-quantum cryptographic algorithms to provide a future-proof security solution for sensitive data exchange across different platforms.

### 1.1 Design Goals

- **Quantum-Resistant Security:** Ensure communications remain secure against quantum computing attacks
- **Performance:** Maintain high throughput and low latency for data transfer
- **Cross-Platform Compatibility:** Support multiple platforms including Rust, C#, embedded systems, and web browsers
- **Streaming Support:** Efficiently handle large data transfers
- **Simple API:** Provide an intuitive interface for easy integration

### 1.2 Security Properties

- **Forward Secrecy:** Session keys cannot be recovered even if long-term keys are compromised
- **Authentication:** Both parties can verify each other's identity
- **Confidentiality:** Data is encrypted to prevent unauthorized access
- **Integrity:** Any tampering with messages can be detected
- **Replay Protection:** Prevents replay attacks using sequence numbers

## 2. Cryptographic Primitives

### 2.1 Key Exchange

- **Algorithm:** CRYSTALS-Kyber (Kyber768)
- **Purpose:** Establish a shared secret between parties
- **Key Sizes:**
  - Public Key: 1184 bytes
  - Secret Key: 2400 bytes
  - Ciphertext: 1088 bytes
  - Shared Secret: 32 bytes

### 2.2 Digital Signatures

- **Algorithm:** CRYSTALS-Dilithium (Dilithium3)
- **Purpose:** Authenticate messages and verify identity
- **Key Sizes:**
  - Public Key: 1952 bytes
  - Secret Key: 4016 bytes
  - Signature: 3293 bytes

### 2.3 Symmetric Encryption

- **Algorithm:** ChaCha20-Poly1305
- **Purpose:** Encrypted and authenticated data transfer
- **Key Size:** 32 bytes (derived from Kyber shared secret)
- **Nonce Size:** 12 bytes
- **Authentication Tag Size:** 16 bytes

### 2.4 Key Derivation

- **Algorithm:** HKDF-SHA256
- **Purpose:** Derive encryption keys from the Kyber shared secret
- **Input:** 32-byte Kyber shared secret
- **Output:** 32-byte ChaCha20-Poly1305 key

## 3. Protocol Flow

### 3.1 Session States

1. **New:** Initial state before any keys are exchanged
2. **KeyExchangeInitiated:** Client has generated and sent its public key
3. **KeyExchangeCompleted:** Shared secret established on both sides
4. **AuthenticationInitiated:** Verification keys exchanged
5. **AuthenticationCompleted:** Signatures verified
6. **Established:** Secure communication channel ready
7. **Closed:** Session terminated

### 3.2 Key Exchange Phase

1. **Client → Server:** Kyber public key
2. **Server:** 
   - Generates shared secret using client's public key
   - Derives encryption key using HKDF
3. **Server → Client:** Kyber ciphertext
4. **Client:**
   - Recovers shared secret using ciphertext and own secret key
   - Derives identical encryption key using HKDF

### 3.3 Authentication Phase

1. **Client → Server:** Dilithium verification key
2. **Server → Client:** Dilithium verification key
3. **Both parties:**
   - Store remote verification key
   - Complete authentication
   - Transition to Established state

### 3.4 Data Transfer Phase

1. **Sender:**
   - Creates nonce from sequence number and message type
   - Encrypts data with ChaCha20-Poly1305
   - Signs encrypted data with Dilithium signing key
   - Assembles message with header, encrypted data, and signature
   - Increments sequence number
2. **Receiver:**
   - Verifies header
   - Verifies sequence number to prevent replay attacks
   - Verifies signature using sender's verification key
   - Decrypts data using ChaCha20-Poly1305
   - Increments sequence number

### 3.5 Streaming

1. **Sender:**
   - Divides large data into chunks (default: 16KB)
   - Encrypts and signs each chunk as a separate message
2. **Receiver:**
   - Processes each chunk independently
   - Optionally reassembles chunks for complete data

### 3.6 Session Termination

1. **Either party:**
   - Sends Close message
   - Transitions to Closed state
   - Destroys session keys

## 4. Message Format

### 4.1 Message Header (10 bytes)

```
+------+-----------+---------------+-----------------+
| Version | Message Type | Sequence Number | Payload Length |
| (1 byte) | (1 byte)     | (4 bytes)       | (4 bytes)      |
+------+-----------+---------------+-----------------+
```

- **Version:** Protocol version (current: 0x01)
- **Message Type:** Type of the message
- **Sequence Number:** Message sequence number (big-endian)
- **Payload Length:** Length of the payload in bytes (big-endian)

### 4.2 Message Types

- **0x01:** KeyExchange
- **0x02:** Signature
- **0x03:** Data
- **0x04:** Ack
- **0x05:** Close
- **0xFF:** Error

### 4.3 Data Message Format

```
+--------+----------------+----------+
| Header | Encrypted Data | Signature |
| (10B)  | (variable)     | (3293B)   |
+--------+----------------+----------+
```

### 4.4 Close Message Format

```
+--------+
| Header |
| (10B)  |
+--------+
```

### 4.5 Ack Message Format

```
+--------+----------------+
| Header | Sequence Number |
| (10B)  | (4B)            |
+--------+----------------+
```

## 5. Error Handling

### 5.1 Error Codes

- **0x01:** VersionMismatch
- **0x02:** InvalidFormat
- **0x03:** AuthFailure
- **0x04:** DecryptionFailure
- **0x05:** SequenceMismatch
- **0x10:** InternalError

### 5.2 Error Message Format

```
+--------+------------+
| Header | Error Code |
| (10B)  | (1B)       |
+--------+------------+
```

## 6. Security Considerations

### 6.1 Nonce Generation

- Nonces for ChaCha20-Poly1305 are constructed from:
  - First 4 bytes: Sequence number
  - 5th byte: Message type
  - Last 7 bytes: Random data

### 6.2 Replay Protection

- Strictly increasing sequence numbers
- Messages with unexpected sequence numbers are rejected

### 6.3 Side-Channel Considerations

- Implementations should use constant-time operations where appropriate
- Avoid timing leaks in cryptographic operations

### 6.4 Key Management

- Session keys are ephemeral and unique per session
- Long-term keys (Dilithium) should be properly secured
- Key rotation mechanisms should be implemented

## 7. Implementation Guidelines

### 7.1 Memory Considerations

- Buffer sizes should account for header overhead and signatures
- For constrained environments, streaming with appropriate chunk sizes is recommended

### 7.2 Performance Optimization

- Use hardware acceleration where available
- Batch operations when processing multiple messages
- Consider pre-computing frequently used values

### 7.3 Cross-Platform Compatibility

- Ensure consistent byte ordering (big-endian)
- Account for platform-specific memory alignment requirements
- Test thoroughly across all target platforms

## 8. Example Implementations

The protocol is implemented in the following languages:

- **Rust** (core implementation)
- **C#** (via FFI bindings)
- **JavaScript/WebAssembly** (for browser environments)

## Appendix A: Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| VERSION | 0x01 | Protocol version |
| HEADER_SIZE | 10 | Size of message header in bytes |
| KYBER_PUBLIC_KEY_BYTES | 1184 | Size of Kyber public key |
| KYBER_SECRET_KEY_BYTES | 2400 | Size of Kyber secret key |
| KYBER_CIPHERTEXT_BYTES | 1088 | Size of Kyber ciphertext |
| KYBER_SHARED_SECRET_BYTES | 32 | Size of Kyber shared secret |
| DILITHIUM_PUBLIC_KEY_BYTES | 1952 | Size of Dilithium public key |
| DILITHIUM_SECRET_KEY_BYTES | 4016 | Size of Dilithium secret key |
| DILITHIUM_SIGNATURE_BYTES | 3293 | Size of Dilithium signature |
| CHACHA_TAG_SIZE | 16 | Size of ChaCha20-Poly1305 tag |
| CHACHA_NONCE_SIZE | 12 | Size of ChaCha20-Poly1305 nonce |
| MAX_CHUNK_SIZE | 16384 | Default maximum chunk size |

## Appendix B: Protocol Flow Diagram

```
Client                                      Server
------                                      ------
  |                                            |
  |--- Kyber Public Key ---------------------->|
  |                                            |
  |<-- Kyber Ciphertext -----------------------|
  |                                            |
  |--- Dilithium Verification Key ------------>|
  |                                            |
  |<-- Dilithium Verification Key -------------|
  |                                            |
  |=== Secure Channel Established ============ |
  |                                            |
  |--- Encrypted & Signed Data --------------->|
  |                                            |
  |<-- Encrypted & Signed Data ----------------|
  |                                            |
  |--- Encrypted & Signed Data (Streaming) --->|
  |                                            |
  |--- Close Message ------------------------->|
  |                                            |
```

## Appendix C: References

1. NIST Post-Quantum Cryptography Standardization
2. CRYSTALS-Kyber specification
3. CRYSTALS-Dilithium specification
4. ChaCha20-Poly1305 (RFC 8439)
5. HKDF (RFC 5869)
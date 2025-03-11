```
# 🚀 Post-Quantum Cryptography Streaming Protocol

A high-performance streaming protocol leveraging **NIST-standardized post-quantum cryptography** (PQC) for **secure** and **future-proof** communication across **Rust, C#, embedded systems, and web browsers**.

## Overview  

This protocol ensures **quantum-resistant encryption** for secure communication by using:  
- **CRYSTALS-Kyber (Kyber768)** – Secure key exchange  
- **CRYSTALS-Dilithium (Dilithium3)** – Digital signatures  
- **ChaCha20-Poly1305** – Fast and secure symmetric encryption  
- **Chunked streaming** – Efficient large data transfer  
- **Multi-language support** – Rust, C#, WebAssembly, and more  

## Features  

- **Quantum-resistant security:** Protects against quantum attacks with NIST-selected PQC algorithms  
- **Efficient streaming:** Chunk-based data transfer for optimal performance  
- **Secure key exchange:** Robust ephemeral key agreement  
- **Authentication:** Mutual endpoint verification  
- **Bidirectional communication:** Full-duplex secure channel  
- **Cross-platform:** Works on desktop, web, mobile, and embedded systems  
- **Simple API:** Intuitive interface for easy integration  

## Project Structure  

```
QStream/
├── Cargo.toml             # Rust package configuration
├── README.md              # This file
├── src/                   # Core Rust implementation
│   ├── lib.rs             # Library entry point
│   ├── error.rs           # Error handling
│   ├── header.rs          # Message headers
│   ├── session.rs         # PQC session logic
│   ├── streaming.rs       # Streaming utilities
│   ├── types.rs           # Common types/constants
│   ├── ffi/               # Foreign Function Interface (FFI)
│   │   ├── mod.rs         # FFI module
│   │   └── c_api.rs       # C-compatible API
│   └── wasm/              # WebAssembly bindings
│       ├── mod.rs         # WASM exports
│       └── bindings.rs    # Web browser bindings
├── examples/              # Example implementations
│   ├── client.rs          # Rust client
│   ├── server.rs          # Rust server
│   ├── browser_example.js # JavaScript browser example
│   └── csharp/            # C# examples
│       ├── PqcProtocol.cs # C# protocol implementation
│       └── Example.cs     # C# example app
└── tests/                 # Integration tests
```

## Installation  

### Rust  

Add to your `Cargo.toml`:  

```toml
[dependencies]
pqc-protocol = "0.1.0"
```

### C#  

1. **Build the Rust library with C FFI enabled:**  
   ```sh
   cargo build --release --features ffi
   ```

2. **Copy the resulting shared library** (libpqc_protocol.so, pqc_protocol.dll, or libpqc_protocol.dylib) to your .NET project.

3. **Include the `PqcProtocol.cs` file** in your project.

---

**License:** MIT
```

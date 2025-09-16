## **Comprehensive Arkfile Streaming Download Implementation Plan**

The current Arkfile system implements a sophisticated zero-knowledge architecture where the **server never sees plaintext file content** and **client-side cryptography handles all encryption/decryption operations**. Core cryptographic functions reside in the `crypto/` package which is imported by the WASM client (`client/main.go`) for browser-based operations and `cryptocli` for offline cryptographic operations, while the `arkfile-client` purely handles API communication without importing cryptographic functions. The frontend TypeScript code serves exclusively as UI logic calling WASM functions for actual cryptographic operations.

## **Current Architecture Analysis**
The existing system maintains zero-knowledge properties through: **`arkfile-client` for authenticated server communication** → **server-side storage with encrypted data** → **client-side WASM decryption in browser** → **`cryptocli` for file-level encryption/decryption**. The current JSON-based download API (`/api/download/{filename}`) returns encrypted data in a `data` field, which the frontend processes through WASM functions (`decryptFileWithSecureSession`, `decryptFile`) before creating a download blob. 

## **Core Problem Addressed**  
The system's current `DownloadFile` function loads entire files into server memory using `io.ReadAll(reader)`, causing **critical memory exhaustion with large files** (10GB+ files killing servers), blocking concurrent downloads, and creating inefficiencies through unnecessary JSON wrapper overhead.

## **Streaming Solution Strategy**
Replace the memory-bounded JSON API with **separate metadata and binary streaming endpoints** while preserving the zero-knowledge architecture. Implement **`GET /api/download/{fileId}/meta`** for secure metadata delivery (encrypted filename/hints/FEK data) and **`GET /api/download/{fileId}/stream`** for direct binary file streaming, eliminating JSON serialization overhead and enabling **truly bounded memory usage** regardless of file size.

## **Architecture Preservation**
The streaming implementation maintains zero-knowledge properties through: **`arkfile-client` download coordination** → **separate metadata JSON response** → **binary stream response** → **WASM decryption of encrypted binary data** → **browser blob creation**. All cryptographic operations remain client-side WASM, server continues to never see plaintext data.

## **Implementation Structure**
Create **`handlers/streaming.go`** for dedicated streaming handlers, update **`test-app-curl.sh`** for testing both approaches, modify **`arkfile-client`** to coordinate metadata and stream requests with minimal logic changes since it doesn't handle crypto. The **`crypto/`** package and WASM implementations require no changes as streaming doesn't impact client-side encryption/decryption workflows.

## **Zero-Knowledge Compliance Validation**
This streaming approach enhances security by separating sensitive encrypted metadata transport (JSON) from encrypted binary data transport (direct stream), ensuring: **server never learns file content** → **server never learns plaintext metadata** → **no IP logging exposure** → **server knows nothing about file nature**. The architecture maintains the fundamental design where **`cryptocli`** generates encrypted data, **`arkfile-client`** handles transport authentication, **`server`** stores encrypted blobs, and **`WASM`** client-side operations handle decryption.

## **Migration and Testing Strategy**
As a greenfield deployment with no current users, implement streaming as the immediate default approach with the JSON endpoint completely removed, using **`dev-reset.sh`** to redeploy the app, and **`test-app-curl.sh`** for comprehensive end-to-end testing of: encrypt → upload → **stream endpoint** → decrypt workflow verification with a fixed, static 100 MB file. Validate client-side memory efficiency and concurrent download performance. At later stages we may add larger files to validate the approach and performance further.

## **Frontend Integration**  
The frontend requires no major changes since it receives encrypted binary data through HTTP responses regardless of transport mechanism. The TypeScript code continues calling WASM functions for decryption, maintaining the secure separation where JavaScript never handles actual cryptographic operations.

## **Production Readiness Considerations**
The streaming implementation transforms Arkfile from a memory-bounded to a **truly scalable binary streaming service** capable of handling enterprise-scale multi-TB file operations with resource efficiency similar to **AWS S3/AMZN_SL**, while maintaining the unique blend of **client-side WASM cryptography** and **zero-knowledge S3 storage** that defines the Arkfile architecture.

This architectural change solves the memory scaling issue while enhanced the existing zero-knowledge security model through cleaner separation between metadata and binary transport channels.
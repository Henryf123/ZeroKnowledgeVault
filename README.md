# ZeroKnowledgeVault
A client-side terminal user interface (TUI) app designed to prepare sensitive documents for secure, encrypted cloud storage

### Overview
ZeroKnowledgeVault protects sensitive personal documents such as tax records or medical forms by keeping them securely encrypted on disk. Built with Python and Textual, it utilizes low-level cryptographic primitives to process local files via chunked encryption streams into an isolated vault. Users can export their vault into a single, tamper-evident encrypted package suitable for cloud sync or offline archiving.

### Key Features
* Authenticated Stream Encryption: Uses AES-256-GCM with unique nonces to encrypt files in chunked streams to handle large document imports with minimal memory overhead.
* Hierarchical Key Management: Derives master and per-file encryption keys locally using PBKDF2HMAC and HKDF.
* Portable Backup Packages: Exports all vault storage and metadata into an encrypted, password-protected archive for seamless cloud sync and restoration.
* Data Integrity Verification: Utilizes SHA-256 checksums and AES-GCM authentication tags to verify data integrity.
* Temporary Workspace: Decrypts files into an isolated workspace that is automatically shredded upon application exit.
* Fast Metadata Search & Indexing: Utilizes a local SQLite database, allowing fast filtering by title, company, tag, or tax year.
* Batch Operations: Built-in multi-selection support for bulk file marking, viewing, and deletion.

### To run this application
macOS
```
pip install -r requirements.txt
python3 -m src.main
```

### Disclaimer
This application currently is only compatible with macOS it does not run on any other operating system. This application also has not undergone a formal third-party security audit. Use with appropriate discretion
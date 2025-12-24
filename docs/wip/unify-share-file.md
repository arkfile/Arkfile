# Unify Share File System

**Goals for Share Creation and Access**

Our primary goal is to establish a unified, secure, and user-friendly system for sharing files that maintains our zero-knowledge architecture. We aim to support sharing of files regardless of their original encryption method, ensuring a seamless experience for the owner and a simple experience for the recipient. The client application must handle the cryptographic complexity internally while presenting a clear and consistent interface to the user.

**The Three Password Types**

To avoid ambiguity, it is critical to distinguish between the three password types used in the system. First is the Account Password, which is the owner's main login password used to derive the Account Key. This key is used to encrypt the majority of user files, referred to as Account-Encrypted Files. Second is the Custom Password, which is an optional password set by the owner at the time of upload to encrypt a specific file. These Custom-Encrypted Files are not encrypted with the Account Key and require the specific custom password to be unlocked/decrypted. Third is the Share Password, which is a new, unique password explicitly chosen by the owner specifically when creating a share link. This is the password the recipient must enter to access the file. The Share Password is distinct from both the Account Password and the Custom Password.

**Unified Share Creation Workflow**

The share creation process is designed to be consistent for the owner regarding the output, which is always a secure link protected by a Share Password. When a user initiates a share, they are always required to explicitly set a Share Password for the recipient. The client application then performs the necessary cryptographic operations to create the share, which differs based on the source file's encryption.

For Account-Encrypted Files, the client application leverages the user's active session to make the process seamless. Since the user is logged in, their Account Key is already cached in memory. The client application uses this cached Account Key to silently decrypt the file's encryption key, then re-encrypts that key with the new Share Password set by the owner. This allows the owner to create shares without being prompted to re-enter their own credentials, providing a smooth user experience.

For Custom-Encrypted Files, the client application cannot automatically unlock the file because the encryption key is protected by a password that is not cached in the session. In this case, the client application must prompt the owner to enter the Original Custom Password for that specific file. Once the owner provides the correct password, the client application decrypts the file's encryption key and proceeds to re-encrypt it with the new Share Password. This ensures that even files with custom encryption can be shared securely, provided the owner can prove their authorization.

**Unified Share Access Workflow**

The experience for the recipient is designed to be secure, efficient, and identical regardless of the source file's encryption. When a recipient clicks a share link, their client application (browser or CLI) first downloads the Share Envelope, a small metadata package. The client then prompts the recipient to enter the Share Password. Upon entry, the client locally derives the Share Key and attempts to decrypt the Share Envelope using Authenticated Encryption (AES-GCM). This step serves two critical purposes: it verifies the password immediately without downloading the full file, and it reveals the File Encryption Key (FEK) and a unique Download Token. If decryption fails, the client notifies the recipient instantly. If successful, the client presents the decrypted Download Token to the server to authorize the transfer of the encrypted file content. This ensures that only a recipient with the correct password can consume server bandwidth. Finally, once the encrypted file is downloaded, the client uses the previously decrypted FEK to unlock the file content locally on the recipient's device. Notably, the share system does not require recipients to have an account or login in order to access shared files. They only need the link/ID/share password to download and decrypt a given shared file.

**Current State and Implementation Requirements**

The current implementation requires updates to align with this unified vision. For CLI users, the client interface needs to be updated to clearly distinguish between these flows. It must ensure that sharing Account-Encrypted files utilizes the cached keys where possible to avoid unnecessary prompts, while correctly prompting for the decryption password when sharing Custom-Encrypted files. (CLI tools need to be updated to create a secure way of caching the Account Key; TBD how to do this securely and safely on different Linux/BSD systems.)

For Web App users, the interface currently lacks the logic to intelligently handle these two scenarios. The share creation flow needs to be updated to check the file's encryption type. If the file is Account-Encrypted, it should use the cached Account Key to unlock the file silently. If the file is Custom-Encrypted, it must prompt the owner for the original password. In all cases, the UI must require the owner to set a Share Password for the recipient.

Once all the code changes are in place for the CLI clients, the Web App clients and in the code for the server itself, we can use dev-reset.sh to redeploy everything, and e2e-test.sh to test everything (at least for the CLI client portions). NOTE: We will need to update e2e-test.sh to make sure it aligns with the changes made to the app for the share system, and make sure that we have full end-to-end tests of sharing and decryption for both encrypted file types: Account Password-based and Custom Password-based. The tests should be done while logged out to simulate a non-user visitor/recipient without an account as well.

**Cryptographic Mechanics and Key Independence**

To ensure zero-knowledge security and data availability, the system utilizes a specific key management architecture based on File Encryption Keys (FEKs) and Key Envelopes. Every file is encrypted with a unique, random symmetric key called the FEK. This key is generated on the client side at the time of upload and is used to encrypt the actual file content. Crucially, the FEK never changes for the lifetime of the file version, regardless of how many times it is shared or who accesses it.

When the file is first uploaded, the FEK is encrypted using the owner's key (either the Account Key or Custom Password-derived Key). This creates the "Owner's Envelope," which is stored in the database. This envelope ensures that the owner can always decrypt the file using their own credentials.

When a share is created, the client application retrieves the Owner's Envelope and decrypts it to obtain the raw FEK. It then generates a new key derived from the Share Password (the Share Key) and encrypts the raw FEK (along with the Download Token) with this Share Key. This creates a new, separate "Share Envelope" which is stored alongside the share metadata.

It is vital to understand that creating a Share Envelope is a non-destructive additive process. It does *not* modify the original Owner's Envelope or the encrypted file content. The system simply stores an additional encrypted copy of the key. Therefore, the original owner retains full access to their file using their original password (Account or Custom), completely unaffected by the existence of the share or the Share Password. The owner's access path and the recipient's access path are cryptographically independent, meeting at the immutable FEK.

NOTE: The app will need to be updated to add in the Download Token feature, along with other changes to facilitate the intended design and functioning of the secure Share system.

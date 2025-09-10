# fix-file-ops.md

We are trying to prove that the Arkfile app is correctly and securely implemented for zero-knowledge file vault operations. Currently, we are stuck on file metadata decryption (and possibly correct encryption in the first place). After addressing file metatdata decryption, we will look again at file decryption itself.

The key tools to use for this task are `test-app-curl.sh` for the end-to-end testing, and `sudo ./scripts/dev-reset.sh` for whenever we make changes to the app itself.

`arkfile-client` is a CLI tool to perform auth, and get and push data to the Arkfile server.

All critical encryption/decryption related operations happen via `cryptocli` for CLI users.

All actual crypto (encrypt/decrypt) related functions should and must live in the core crypto libraries in the app, which the client apps (CLI and client/main.go (for Go/WASM)) can import from.

---

Example outputs from test-app-curl.sh, where the script is failing:

```
[OK] arkfile-client tool available and ready
[2025-09-10 10:37:46] Step 9: Configuring arkfile-client with a valid session file...
[OK] arkfile-client config and session file created
[2025-09-10 10:37:46] Step 10: Uploading original file using arkfile-client with piped password...
[INFO] Initiating client upload... See log for details: /tmp/tmp.S7hbFvCMEo/upload_output.log
[VERBOSE] Uploading file: e2e-test-file.dat (104857600 bytes)
[VERBOSE] Reading password for FEK encryption...
[VERBOSE] Making POST request to https://localhost:4443/api/uploads/init
[VERBOSE] Response status: 200
[VERBOSE] Response body: {"chunkSize":16777216,"expiresAt":"2025-09-11T10:37:48.780100157-06:00","fileId":"9d31a2f5-b5d2-4f01-ad4d-c867ef564687","sessionId":"d78fb859-99f1-4665-9571-81d26689e835","totalChunks":7}

[VERBOSE] Upload session initialized: d78fb859-99f1-4665-9571-81d26689e835
[VERBOSE] File ID: 9d31a2f5-b5d2-4f01-ad4d-c867ef564687
Uploading e2e-test-file.dat (100.0 MB) in 7 chunks...
[VERBOSE] Uploading chunk 0 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/0
[VERBOSE] Uploading chunk 1 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/1
[VERBOSE] Uploading chunk 2 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/2
[VERBOSE] Uploading chunk 3 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/3
[VERBOSE] Uploading chunk 4 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/4
[VERBOSE] Uploading chunk 5 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/5
[VERBOSE] Uploading chunk 6 to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/chunks/6
[VERBOSE] Making POST request to https://localhost:4443/api/uploads/d78fb859-99f1-4665-9571-81d26689e835/complete
[VERBOSE] Response status: 200
[VERBOSE] Response body: {"encryptedFileSHA256":"8798b429d99a1dc8ffe6603e61cdab031a3e5b743d854c546815c8c00b35375c","fileId":"9d31a2f5-b5d2-4f01-ad4d-c867ef564687","message":"File uploaded successfully","storage":{"available_bytes":1076258406,"limit_bytes":1181116006,"total_bytes":104857600},"storageId":"4445e626-3717-4a23-9ba0-1ea7a7e1b2e1"}

✅ Upload completed successfully
File ID: 9d31a2f5-b5d2-4f01-ad4d-c867ef564687
Storage ID: 4445e626-3717-4a23-9ba0-1ea7a7e1b2e1
Server-side Encrypted SHA256: 8798b429d99a1dc8ffe6603e61cdab031a3e5b743d854c546815c8c00b35375c
Original size: 100.0 MB
Encrypted size: 100.0 MB
[OK] File uploaded successfully. File ID: 9d31a2f5-b5d2-4f01-ad4d-c867ef564687
[2025-09-10 10:37:51] Step 11: Verifying file metadata decryption via cryptocli...
[OK] Uploaded file found in server file listing JSON.
--- DEBUG: Raw file_entry JSON ---
{"file_id":"9d31a2f5-b5d2-4f01-ad4d-c867ef564687","storage_id":"4445e626-3717-4a23-9ba0-1ea7a7e1b2e1","password_type":"account","filename_nonce":"UTNwd1ZTdHVVM2d3UkZBelJFbG1Zdz09","encrypted_filename":"UTNwd1ZTdHVVM2d3UkZBelJFbG1ZMDFCYTJaTlJ6ZzFjRkYzYUV4UlkwdFdSekEzWWtOcVQxcEpRWFpyVm0xQ2Ntb3lVbTk1ZG10c2JUVjE=","sha256sum_nonce":"UVhBd2VISjZiRkZTVUZOU1duRlRWdz09","encrypted_sha256sum":"UVhBd2VISjZiRkZTVUZOU1duRlRWelpVUTJ0T1ZYQlRUbGhhY0RCdE9HdDRVRE40Vm5ScFUzWkVhVmt5Ym0xcWRFd3hiak5qZFdOb1ZsZHFOVXMxV1RoRU9HWkRaRzVvZVcxd1RVWnljV1JuZFdKeFprSkJSMHBWUVVOYU5UQlphbmxSV25Kd1ZqTndOa3BuV1ZVMU0wRnVPVnBLYlZGRU1VWTRQUT09","encrypted_fek":"QVFFYnBZaHZlQVhkVm9FUzhEREdKa3EzNnA4dDBkUExJNCtIa1VsNThlZEQwU2tJMkh0UTY1TllOalYxOTZTOE1wZWIxcEg4clZFaU9GazUzM2s9","size_bytes":104857600,"upload_date":"2025-09-10T16:37:51Z","size_readable":"100.0 MB"}
--- DEBUG: Extracted Values ---
encrypted_fek: QVFFYnBZaHZlQVhkVm9FUzhEREdKa3EzNnA4dDBkUExJNCtIa1VsNThlZEQwU2tJMkh0UTY1TllOalYxOTZTOE1wZWIxcEg4clZFaU9GazUzM2s9
encrypted_filename: UTNwd1ZTdHVVM2d3UkZBelJFbG1ZMDFCYTJaTlJ6ZzFjRkYzYUV4UlkwdFdSekEzWWtOcVQxcEpRWFpyVm0xQ2Ntb3lVbTk1ZG10c2JUVjE=
encrypted_sha256sum: UVhBd2VISjZiRkZTVUZOU1duRlRWelpVUTJ0T1ZYQlRUbGhhY0RCdE9HdDRVRE40Vm5ScFUzWkVhVmt5Ym0xcWRFd3hiak5qZFdOb1ZsZHFOVXMxV1RoRU9HWkRaRzVvZVcxd1RVWnljV1JuZFdKeFprSkJSMHBWUVVOYU5UQlphbmxSV25Kd1ZqTndOa3BuV1ZVMU0wRnVPVnBLYlZGRU1VWTRQUT09
username: arkfile-dev-test-user
--- DEBUG: cryptocli command ---
echo "$TEST_PASSWORD" | /opt/arkfile/bin/cryptocli decrypt-metadata --encrypted-fek "QVFFYnBZaHZlQVhkVm9FUzhEREdKa3EzNnA4dDBkUExJNCtIa1VsNThlZEQwU2tJMkh0UTY1TllOalYxOTZTOE1wZWIxcEg4clZFaU9GazUzM2s9" --encrypted-filename "UTNwd1ZTdHVVM2d3UkZBelJFbG1ZMDFCYTJaTlJ6ZzFjRkYzYUV4UlkwdFdSekEzWWtOcVQxcEpRWFpyVm0xQ2Ntb3lVbTk1ZG10c2JUVjE=" --encrypted-sha256sum "UVhBd2VISjZiRkZTVUZOU1duRlRWelpVUTJ0T1ZYQlRUbGhhY0RCdE9HdDRVRE40Vm5ScFUzWkVhVmt5Ym0xcWRFd3hiak5qZFdOb1ZsZHFOVXMxV1RoRU9HWkRaRzVvZVcxd1RVWnljV1JuZFdKeFprSkJSMHBWUVVOYU5UQlphbmxSV25Kd1ZqTndOa3BuV1ZVMU0wRnVPVnBLYlZGRU1VWTRQUT09" --username "arkfile-dev-test-user"
--- END DEBUG ---
[CLEANUP] Cleaning up temporary files...
```

Example command to try to manually debug file metadata decryption:

```
echo 'MyVacation2025PhotosForFamily!ExtraSecure' | sudo /opt/arkfile/bin/cryptocli decrypt-metadata --encrypted-fek "QVFFYnBZaHZlQVhkV
m9FUzhEREdKa3EzNnA4dDBkUExJNCtIa1VsNThlZEQwU2tJMkh0UTY1TllOalYxOTZTOE1wZWIxcEg4clZFaU9GazUzM2s=" --encrypted-filename "UTNwd1ZTdHVVM2d3UkZBelJFbG1ZMDFCYTJaTlJ6ZzFjRkYzYUV4Ul
kwdFdSekEzWWtOcVQxcEpRWFpyVm0xQ2Ntb3lVbTk1ZG10c2JUVjE=" --encrypted-sha256sum "UVhBd2VISjZiRkZTVUZOU1duRlRWelpVUTJ0T1ZYQlRUbGhhY0RCdE9HdDRVRE40Vm5ScFUzWkVhVmt5Ym0xcWRFd3hiak
5qZFdOb1ZsZHFOVXMxV1RoRU9HWkRaRzVvZVcxd1RVWnljV1JuZFdKeFprSkJSMHBWUVVOYU5UQlphbmxSV25Kd1ZqTndOa3BuV1ZVMU0wRnVPVnBLYlZGRU1VWTRQUT09" --username "arkfile-dev-test-user"
[ERROR] Metadata decryption failed: FEK decryption failed: failed to parse FEK envelope: unsupported version: 0x41 (expected 0x01 for password-based encryption)
```

---
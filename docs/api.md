# Arkfile API Reference

This document provides a reference for the Arkfile API. It is intended for developers who wish to integrate their applications with the Arkfile platform.

## Authentication

All requests to the Arkfile API must be authenticated using a JSON Web Token (JWT). The token should be included in the `Authorization` header of your HTTP request with the `Bearer` scheme.

`Authorization: Bearer <your-jwt-token>`

Tokens can be obtained by making a POST request to the `/login` endpoint with a valid username and password.

## Endpoints

*(This section is under construction and will be updated with detailed endpoint documentation.)*

### File Operations

- **`POST /upload`**: Upload a new file.
- **`GET /download/:filename`**: Download a file.
- **`GET /files`**: List all files for the authenticated user.
- **`DELETE /files/:filename`**: Delete a file.

### Sharing Operations

- **`POST /share`**: Create a new share link for a file.
- **`GET /share/:share_id`**: Access a shared file via a share link.
- **`DELETE /share/:share_id`**: Delete a share link.

### Key Management

- **`POST /files/:filename/keys`**: Add a new decryption key to a file.
- **`GET /files/:filename/keys`**: List all decryption keys for a file.
- **`DELETE /files/:filename/keys/:key_id`**: Remove a decryption key from a file.

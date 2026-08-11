#!/usr/bin/env bun

"use strict";

const fs = require("fs");
const path = require("path");

console.log = () => {};
console.debug = () => {};

function fromBase64(value) {
  return new Uint8Array(Buffer.from(value, "base64"));
}

function fromHex(value) {
  return new Uint8Array(Buffer.from(value, "hex"));
}

function toBase64(value) {
  return Buffer.from(value).toString("base64");
}

function toHex(value) {
  return Buffer.from(value).toString("hex");
}

async function main() {
  const artifactPath = path.resolve(process.argv[2]);
  const opaque = require(artifactPath);
  await opaque.ready;

  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  const ids = { idU: request.username, idS: request.server_id };
  let response;

  switch (request.operation) {
    case "registration_request": {
      const result = opaque.createRegistrationRequest({ pwdU: request.password });
      response = {
        request_b64: toBase64(result.M),
        secret_hex: toHex(result.sec),
      };
      break;
    }
    case "registration_finalize": {
      const result = opaque.finalizeRequest({
        sec: fromHex(request.secret_hex),
        pub: fromBase64(request.response_b64),
        ids,
      });
      response = {
        record_b64: toBase64(result.rec),
        export_key_hex: toHex(result.export_key),
      };
      break;
    }
    case "credential_request": {
      const result = opaque.createCredentialRequest({ pwdU: request.password });
      response = {
        request_b64: toBase64(result.pub),
        secret_hex: toHex(result.sec),
      };
      break;
    }
    case "credential_recover": {
      const result = opaque.recoverCredentials({
        resp: fromBase64(request.response_b64),
        sec: fromHex(request.secret_hex),
        context: "arkfile_auth",
        ids,
      });
      response = {
        auth_b64: toBase64(result.authU),
        export_key_hex: toHex(result.export_key),
      };
      break;
    }
    default:
      throw new Error(`unsupported operation: ${request.operation}`);
  }

  process.stdout.write(JSON.stringify(response));
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});

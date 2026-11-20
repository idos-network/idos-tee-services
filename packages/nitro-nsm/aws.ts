import { readFileSync, writeFileSync } from "node:fs";
import { EncryptCommand, KMSClient } from "@aws-sdk/client-kms";
import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { kmsDecrypt } from "./kms-decrypt.ts";

// The few AWS calls the boot scripts need (shared/aws.ash), so the images don't carry AWS CLI v2.
// Blobs go in and out as base64, the same contract as the CLI's `--query Plaintext/CiphertextBlob`.
// Region and credentials come from the SDK's defaults (AWS_REGION, instance role via IMDS).
const USAGE =
  "usage: node aws.ts kms-encrypt <key id> <base64> | kms-decrypt <base64> | s3-get <bucket> <key> <file> | s3-put-new <bucket> <key> <file>";
const [command, a = "", b = "", c = ""] = process.argv.slice(2);

switch (command) {
  case "kms-encrypt": {
    const { CiphertextBlob } = await new KMSClient().send(
      new EncryptCommand({ KeyId: a, Plaintext: Buffer.from(b, "base64") }),
    );
    console.log(Buffer.from(CiphertextBlob as Uint8Array).toString("base64"));
    break;
  }
  case "kms-decrypt": {
    // With the NSM addon in the image the plaintext only comes back encrypted to the attestation
    console.log((await kmsDecrypt(Buffer.from(a, "base64"))).toString("base64"));
    break;
  }
  case "s3-get": {
    const { Body } = await new S3Client().send(new GetObjectCommand({ Bucket: a, Key: b }));
    if (!Body) {
      throw new Error(`s3://${a}/${b} has no body`);
    }
    writeFileSync(c, await Body.transformToByteArray());
    break;
  }
  case "s3-put-new": {
    // If-None-Match: * - never overwrite an existing object (a LUKS password, a master key)
    await new S3Client().send(
      new PutObjectCommand({ Bucket: a, Key: b, Body: readFileSync(c), IfNoneMatch: "*" }),
    );
    break;
  }
  default:
    throw new Error(USAGE);
}

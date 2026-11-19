import {
  ConditionalCheckFailedException,
  DeleteItemCommand,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
} from "@aws-sdk/client-dynamodb";
import { createAesGcm } from "@idos/tee-common/aes-gcm.ts";
import { traced } from "@idos/tee-common/telemetry.ts";
import { DYNAMODB_ARMED_TABLE, FLE_MASTER_KEY } from "../env.ts";
import type { ArmRequest } from "../utils/dto.ts";

// Region and credentials from the SDK defaults (AWS_REGION, instance role via IMDS).
const client = new DynamoDBClient({});

// Key derived from the master key, which scripts/run.ash decrypts with attestation.
const aead = createAesGcm(FLE_MASTER_KEY, "proxy-armed-v1");

// Item: armedId (S), dataEnc (B), createdAt (N, epoch ms). Everything (incl. the armedId) is in
// one AES-GCM blob, so a table writer can neither swap the host key / environment nor copy a
// blob between records.
export type Armed = ArmRequest & { id: string };

export const storeArmed = traced("db.storeArmed", async (armedId: string, data: ArmRequest) => {
  await client.send(
    new PutItemCommand({
      TableName: DYNAMODB_ARMED_TABLE,
      Item: {
        armedId: { S: armedId },
        dataEnc: { B: aead.encrypt(JSON.stringify({ armedId, ...data })) },
        createdAt: { N: String(Date.now()) },
      },
      // Like the old unique index: never overwrite an existing record.
      ConditionExpression: "attribute_not_exists(armedId)",
    }),
  );
});

export const getArmed = traced("db.getArmed", async (armedId: string): Promise<Armed | null> => {
  const { Item } = await client.send(
    new GetItemCommand({
      TableName: DYNAMODB_ARMED_TABLE,
      Key: { armedId: { S: armedId } },
      ConsistentRead: true,
    }),
  );

  if (!Item?.dataEnc?.B) {
    return null;
  }

  const { armedId: blobArmedId, ...data }: ArmRequest & { armedId: string } = JSON.parse(
    aead.decrypt(Item.dataEnc.B).toString("utf8"),
  );

  if (blobArmedId !== armedId) {
    throw new Error(`Armed record ${armedId} holds a blob for armedId ${blobArmedId}`);
  }

  return { id: armedId, ...data };
});

/** True when a record was deleted, false when there was none. */
export const deleteArmed = traced("db.deleteArmed", async (armedId: string): Promise<boolean> => {
  try {
    await client.send(
      new DeleteItemCommand({
        TableName: DYNAMODB_ARMED_TABLE,
        Key: { armedId: { S: armedId } },
        ConditionExpression: "attribute_exists(armedId)",
      }),
    );
    return true;
  } catch (error) {
    if (error instanceof ConditionalCheckFailedException) return false;
    throw error;
  }
});

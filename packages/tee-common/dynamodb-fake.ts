// In-memory single-table DynamoDB for the services' tests: Put/Get/Delete by hash key, with the
// attribute_(not_)exists conditions the providers use.
// The SDK module is handed in (from vi.mock's importOriginal) instead of imported here, so
// commands and errors are the service's own classes and `instanceof` keeps working (as in fle.ts).

type Item = Record<string, { S?: string }>;
type Input = { Key?: Item; Item?: Item; ConditionExpression?: string };

interface Sdk {
  PutItemCommand: abstract new (...args: never[]) => unknown;
  GetItemCommand: abstract new (...args: never[]) => unknown;
  DeleteItemCommand: abstract new (...args: never[]) => unknown;
  ConditionalCheckFailedException: new (opts: { message: string; $metadata: object }) => Error;
}

export function fakeDynamoDBClient(sdk: Sdk, hashKey: string, items: Map<string, unknown>) {
  return class DynamoDBClient {
    async send(command: { input: Input }) {
      const { input } = command;
      const id = (input.Key ?? input.Item)?.[hashKey]?.S as string;
      const exists = items.has(id);
      const condition = input.ConditionExpression ?? "";
      if (
        (condition.includes("attribute_not_exists") && exists) ||
        (condition.includes("attribute_exists(") && !exists)
      ) {
        throw new sdk.ConditionalCheckFailedException({ message: "condition", $metadata: {} });
      }
      if (command instanceof sdk.PutItemCommand) items.set(id, input.Item);
      else if (command instanceof sdk.GetItemCommand) return { Item: items.get(id) };
      else if (command instanceof sdk.DeleteItemCommand) items.delete(id);
      else throw new Error("unexpected command");
      return {};
    }
  };
}

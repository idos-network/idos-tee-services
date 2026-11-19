// In-memory single-table DynamoDB for the services' tests: Put/Get/Delete by hash key, with the
// attribute_(not_)exists conditions the providers use, and Scan with a numeric
// "<attr> < :value" filter, paged by `pageSize` to exercise LastEvaluatedKey.
// The SDK module is handed in (from vi.mock's importOriginal) instead of imported here, so
// commands and errors are the service's own classes and `instanceof` keeps working (as in fle.ts).

type Item = Record<string, { S?: string; N?: string }>;
type Input = {
  Key?: Item;
  Item?: Item;
  ConditionExpression?: string;
  FilterExpression?: string;
  ExpressionAttributeValues?: Item;
  ExclusiveStartKey?: Item;
};

interface Sdk {
  PutItemCommand: abstract new (...args: never[]) => unknown;
  GetItemCommand: abstract new (...args: never[]) => unknown;
  DeleteItemCommand: abstract new (...args: never[]) => unknown;
  ScanCommand: abstract new (...args: never[]) => unknown;
  ConditionalCheckFailedException: new (opts: { message: string; $metadata: object }) => Error;
}

export function fakeDynamoDBClient(
  sdk: Sdk,
  hashKey: string,
  items: Map<string, unknown>,
  pageSize = Number.POSITIVE_INFINITY,
) {
  function scan(input: Input) {
    const ids = [...items.keys()];
    const from = input.ExclusiveStartKey
      ? ids.indexOf(input.ExclusiveStartKey[hashKey]?.S ?? "") + 1
      : 0;
    const page = ids.slice(from, from + pageSize);
    const [, attr, value] = input.FilterExpression?.match(/^(\w+) < (:\w+)$/) ?? [];
    const limit = Number(input.ExpressionAttributeValues?.[value ?? ""]?.N);
    const matches = page
      .map((id) => items.get(id) as Item)
      .filter((item) => !attr || Number(item[attr]?.N) < limit)
      .map((item) => ({ [hashKey]: item[hashKey] }));
    const last = page.at(-1);
    return {
      Items: matches,
      LastEvaluatedKey:
        from + pageSize < ids.length && last ? { [hashKey]: { S: last } } : undefined,
    };
  }

  return class DynamoDBClient {
    async send(command: { input: Input }) {
      const { input } = command;
      if (command instanceof sdk.ScanCommand) return scan(input);
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

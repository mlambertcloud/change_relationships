import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  DeleteCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import type { BaseEntity, Connection, EntityType } from "./types.js";

const TABLE_NAME = process.env.TABLE_NAME || "change-relationship-cards";

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client, {
  marshallOptions: { removeUndefinedValues: true },
});

export function nowIso() {
  return new Date().toISOString();
}

export function toEntityItem(entity: BaseEntity) {
  return {
    PK: `ITEM#${entity.id}`,
    SK: "ITEM",
    GSI1PK: `TYPE#${entity.type}`,
    GSI1SK: `NAME#${entity.name.toLowerCase()}`,
    ...entity,
  };
}

export function toConnectionItem(conn: Connection) {
  return {
    PK: `CONNECTION#${conn.id}`,
    SK: "CONNECTION",
    GSI2PK: `FROM#${conn.fromId}`,
    GSI2SK: `TO#${conn.toId}`,
    ...conn,
  };
}

export async function getEntity(id: string) {
  const resp = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `ITEM#${id}`, SK: "ITEM" },
    })
  );
  return resp.Item as BaseEntity | undefined;
}

export async function listEntitiesByType(type: EntityType) {
  const resp = await docClient.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: "GSI1",
      KeyConditionExpression: "GSI1PK = :pk",
      ExpressionAttributeValues: { ":pk": `TYPE#${type}` },
    })
  );
  return (resp.Items ?? []) as BaseEntity[];
}

export async function putEntity(entity: BaseEntity) {
  await docClient.send(
    new PutCommand({ TableName: TABLE_NAME, Item: toEntityItem(entity) })
  );
}

export async function deleteEntity(id: string) {
  await docClient.send(
    new DeleteCommand({
      TableName: TABLE_NAME,
      Key: { PK: `ITEM#${id}`, SK: "ITEM" },
    })
  );
}

export async function updateEntity(id: string, updates: Partial<BaseEntity>) {
  const expressions: string[] = [];
  const values: Record<string, unknown> = {};
  const names: Record<string, string> = {};
  for (const [key, value] of Object.entries(updates)) {
    if (key === "id" || key === "type") continue;
    const attrName = `#${key}`;
    const valueName = `:${key}`;
    expressions.push(`${attrName} = ${valueName}`);
    names[attrName] = key;
    values[valueName] = value;
  }
  if (!expressions.length) return;
  await docClient.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `ITEM#${id}`, SK: "ITEM" },
      UpdateExpression: `SET ${expressions.join(", ")}`,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
    })
  );
}

export async function getConnection(id: string) {
  const resp = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `CONNECTION#${id}`, SK: "CONNECTION" },
    })
  );
  return resp.Item as Connection | undefined;
}

export async function listConnectionsByFrom(fromId: string) {
  const resp = await docClient.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: "GSI2",
      KeyConditionExpression: "GSI2PK = :pk",
      ExpressionAttributeValues: { ":pk": `FROM#${fromId}` },
    })
  );
  return (resp.Items ?? []) as Connection[];
}

export async function putConnection(conn: Connection) {
  await docClient.send(
    new PutCommand({ TableName: TABLE_NAME, Item: toConnectionItem(conn) })
  );
}

export async function deleteConnection(id: string) {
  await docClient.send(
    new DeleteCommand({
      TableName: TABLE_NAME,
      Key: { PK: `CONNECTION#${id}`, SK: "CONNECTION" },
    })
  );
}

export async function scanAll() {
  const items: Record<string, unknown>[] = [];
  let lastKey: Record<string, unknown> | undefined = undefined;
  do {
    const resp = await docClient.send(
      new ScanCommand({ TableName: TABLE_NAME, ExclusiveStartKey: lastKey })
    );
    if (resp.Items) items.push(...resp.Items);
    lastKey = resp.LastEvaluatedKey as Record<string, unknown> | undefined;
  } while (lastKey);
  const nodes = items.filter((item) => item.SK === "ITEM") as unknown as BaseEntity[];
  const links = items.filter((item) => item.SK === "CONNECTION") as unknown as Connection[];
  return { nodes, links };
}

export async function getSchema() {
  const resp = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: "SCHEMA", SK: "TEMPLATE" },
    })
  );
  return resp.Item?.value as unknown | undefined;
}

export async function putSchema(value: unknown) {
  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        PK: "SCHEMA",
        SK: "TEMPLATE",
        value,
        updatedAt: nowIso(),
      },
    })
  );
}

type UserNote = {
  entityId: string;
  userId: string;
  notes: string;
  updatedAt: string;
};

type CommunityNote = {
  entityId: string;
  notes: string;
  updatedAt: string;
};

export async function getUserNote(entityId: string, userId: string) {
  const resp = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `NOTE#${entityId}`, SK: `USER#${userId}` },
    })
  );
  return resp.Item as UserNote | undefined;
}

export async function putUserNote(entityId: string, userId: string, notes: string) {
  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        PK: `NOTE#${entityId}`,
        SK: `USER#${userId}`,
        entityId,
        userId,
        notes,
        updatedAt: nowIso(),
      },
    })
  );
}

export async function getCommunityNote(entityId: string) {
  const resp = await docClient.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `COMMUNITY#${entityId}`, SK: "COMMUNITY" },
    })
  );
  return resp.Item as CommunityNote | undefined;
}

export async function putCommunityNote(entityId: string, notes: string) {
  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        PK: `COMMUNITY#${entityId}`,
        SK: "COMMUNITY",
        entityId,
        notes,
        updatedAt: nowIso(),
      },
    })
  );
}

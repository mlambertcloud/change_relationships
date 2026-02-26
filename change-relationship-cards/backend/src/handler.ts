import { randomUUID } from "node:crypto";
import {
  deleteConnection,
  deleteEntity,
  getConnection,
  getCommunityNote,
  getEntity,
  getSchema,
  getUserNote,
  listConnectionsByFrom,
  listEntitiesByType,
  nowIso,
  putCommunityNote,
  putConnection,
  putEntity,
  putSchema,
  putUserNote,
  scanAll,
  updateEntity,
} from "./db.js";
import type { BaseEntity, Connection, EntityType } from "./types.js";
import { requireGroup, verifyAuthHeader } from "./auth.js";

function response(statusCode: number, body: unknown) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization",
    },
    body: JSON.stringify(body),
  };
}

function parseBody(event: any) {
  if (!event.body) return undefined;
  try {
    return JSON.parse(event.body);
  } catch {
    return undefined;
  }
}

export async function handler(event: any) {
  if (event.requestContext?.http?.method === "OPTIONS") {
    return response(200, { ok: true });
  }

  const method = event.requestContext?.http?.method || event.httpMethod;
  const path = event.rawPath || event.path || "/";
  const query = event.queryStringParameters || {};

  const isPublicRead = method === "GET" && path === "/health";

  let authPayload: Record<string, unknown> | null = null;
  if (!isPublicRead) {
    try {
      authPayload = await verifyAuthHeader(
        event.headers?.authorization || event.headers?.Authorization
      );
    } catch {
      return response(401, { error: "unauthorized" });
    }
  }

  const requireRoles = (allowed: string[]) => {
    if (!authPayload) return false;
    return requireGroup(authPayload, allowed);
  };

  if (method === "GET" && path === "/health") {
    return response(200, { ok: true, service: "change-relationship-api" });
  }

  if (method === "GET" && path === "/graph") {
    const graph = await scanAll();
    return response(200, graph);
  }

  if (method === "GET" && path.startsWith("/notes/")) {
    if (!authPayload?.sub || typeof authPayload.sub !== "string") {
      return response(401, { error: "unauthorized" });
    }
    const id = path.split("/")[2];
    const note = await getUserNote(id, authPayload.sub);
    return response(200, { notes: note?.notes ?? "" });
  }

  if (method === "GET" && path.startsWith("/community-notes/")) {
    const id = path.split("/")[2];
    const note = await getCommunityNote(id);
    return response(200, { notes: note?.notes ?? "" });
  }

  if (method === "GET" && path === "/schema") {
    if (!requireRoles(["admin"])) return response(403, { error: "forbidden" });
    const schema = await getSchema();
    return response(200, schema || {});
  }

  if (method === "PUT" && path === "/schema") {
    if (!requireRoles(["admin"])) return response(403, { error: "forbidden" });
    const body = parseBody(event);
    if (!body) return response(400, { error: "body required" });
    await putSchema(body);
    return response(200, { ok: true });
  }

  if (method === "GET" && path === "/items") {
    const type = query.type as EntityType | undefined;
    if (!type) return response(400, { error: "type is required" });
    const items = await listEntitiesByType(type);
    return response(200, items);
  }

  if (method === "GET" && path.startsWith("/items/")) {
    const id = path.split("/")[2];
    const item = await getEntity(id);
    if (!item) return response(404, { error: "not found" });
    return response(200, item);
  }

  if (method === "POST" && path === "/items") {
    if (!requireRoles(["admin", "editor"])) return response(403, { error: "forbidden" });
    const body = parseBody(event) as Partial<BaseEntity> | undefined;
    if (!body?.type || !body?.name) return response(400, { error: "type and name are required" });
    const now = nowIso();
    const entity: BaseEntity = {
      id: body.id ?? randomUUID(),
      type: body.type,
      name: body.name,
      description: body.description,
      shortDescription: body.shortDescription,
      startDate: body.startDate,
      endDate: body.endDate,
      division: body.division,
      service: body.service,
      risk: body.risk,
      aiScore: body.aiScore ?? null,
      timeWindow: body.timeWindow,
      attributes: body.attributes,
      notes: body.notes,
      tags: body.tags ?? [],
      createdAt: now,
      updatedAt: now,
    };
    await putEntity(entity);
    return response(201, entity);
  }

  if (method === "PUT" && path.startsWith("/items/")) {
    if (!requireRoles(["admin", "editor"])) return response(403, { error: "forbidden" });
    const id = path.split("/")[2];
    const body = parseBody(event) as Partial<BaseEntity> | undefined;
    if (!body) return response(400, { error: "body required" });
    await updateEntity(id, { ...body, updatedAt: nowIso() });
    const updated = await getEntity(id);
    return response(200, updated);
  }

  if (method === "PUT" && path.startsWith("/notes/")) {
    if (!authPayload?.sub || typeof authPayload.sub !== "string") {
      return response(401, { error: "unauthorized" });
    }
    const id = path.split("/")[2];
    const body = parseBody(event) as { notes?: string } | undefined;
    const notes = typeof body?.notes === "string" ? body.notes : "";
    await putUserNote(id, authPayload.sub, notes);
    return response(200, { notes });
  }

  if (method === "PUT" && path.startsWith("/community-notes/")) {
    const id = path.split("/")[2];
    const body = parseBody(event) as { notes?: string } | undefined;
    const notes = typeof body?.notes === "string" ? body.notes : "";
    await putCommunityNote(id, notes);
    return response(200, { notes });
  }

  if (method === "DELETE" && path.startsWith("/items/")) {
    if (!requireRoles(["admin"])) return response(403, { error: "forbidden" });
    const id = path.split("/")[2];
    await deleteEntity(id);
    return response(204, {});
  }

  if (method === "GET" && path === "/connections") {
    const fromId = query.fromId as string | undefined;
    if (!fromId) return response(400, { error: "fromId is required" });
    const links = await listConnectionsByFrom(fromId);
    return response(200, links);
  }

  if (method === "GET" && path.startsWith("/connections/")) {
    const id = path.split("/")[2];
    const link = await getConnection(id);
    if (!link) return response(404, { error: "not found" });
    return response(200, link);
  }

  if (method === "POST" && path === "/connections") {
    if (!requireRoles(["admin", "editor"])) return response(403, { error: "forbidden" });
    const body = parseBody(event) as Partial<Connection> | undefined;
    if (!body?.type || !body?.fromId || !body?.toId) {
      return response(400, { error: "type, fromId, toId are required" });
    }
    const conn: Connection = {
      id: body.id ?? randomUUID(),
      type: body.type,
      fromId: body.fromId,
      toId: body.toId,
      createdAt: nowIso(),
    };
    await putConnection(conn);
    return response(201, conn);
  }

  if (method === "DELETE" && path.startsWith("/connections/")) {
    if (!requireRoles(["admin"])) return response(403, { error: "forbidden" });
    const id = path.split("/")[2];
    await deleteConnection(id);
    return response(204, {});
  }

  return response(404, { error: "route not found" });
}

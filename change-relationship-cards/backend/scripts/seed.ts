import fs from "node:fs";
import path from "node:path";
import {
  deleteConnection,
  deleteEntity,
  nowIso,
  putConnection,
  putEntity,
  putSchema,
  scanAll,
} from "../src/db.js";
import type { BaseEntity, Connection, ConnectionType, EntityType } from "../src/types.js";

const DATA_PATH =
  process.env.CHANGE_DATA_PATH ||
  path.join("..", "data", "changes_tomorrow.txt");
const RESET_TABLE = process.env.RESET_TABLE === "true";

const defaultSchema = {
  types: [
    "change",
    "division",
    "service",
    "server",
    "application",
    "capability",
    "ip",
    "risk",
    "time_window",
  ],
  relationships: [
    "belongs_to",
    "impacts",
    "touches",
    "uses_ip",
    "affects",
    "depends_on",
    "rated_as",
    "scheduled_in",
  ],
};

function slugify(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function makeId(type: EntityType, name: string) {
  const slug = slugify(name) || "unknown";
  return `${type}-${slug}`;
}

function parseFixedWidthTable(text: string) {
  const lines = text.split(/\r?\n/);
  const headerIndex = lines.findIndex(
    (line) => line.trim().startsWith("number") && line.includes("|")
  );
  if (headerIndex === -1) {
    throw new Error("Header row not found in data file.");
  }
  const headerLine = lines[headerIndex];
  const pipePositions = Array.from(headerLine.matchAll(/\|/g)).map(
    (match) => match.index ?? 0
  );
  const spans: Array<[number, number | null]> = [];
  let start = 0;
  for (const pos of pipePositions) {
    spans.push([start, pos]);
    start = pos + 1;
  }
  spans.push([start, null]);

  const columns = spans.map(([s, e]) =>
    headerLine.slice(s, e ?? undefined).trim()
  );

  const rows: Record<string, string>[] = [];
  for (let i = headerIndex + 2; i < lines.length; i += 1) {
    const rawLine = lines[i];
    if (!rawLine.startsWith("CHG")) continue;
    const line =
      rawLine.length < pipePositions[pipePositions.length - 1]
        ? rawLine.padEnd(pipePositions[pipePositions.length - 1] + 1, " ")
        : rawLine;
    const values = spans.map(([s, e]) =>
      line.slice(s, e ?? undefined).trimEnd()
    );
    const row: Record<string, string> = {};
    columns.forEach((col, idx) => {
      row[col] = (values[idx] || "").trim();
    });
    rows.push(row);
  }
  return rows;
}

function parseTimeWindow(startDate?: string, endDate?: string) {
  if (!startDate || !endDate) return "";
  const start = startDate.trim();
  const end = endDate.trim();
  if (!start || !end) return "";
  const startDay = start.slice(0, 10);
  const startTime = start.slice(11, 16);
  const endDay = end.slice(0, 10);
  const endTime = end.slice(11, 16);
  if (startDay === endDay) {
    return `${startDay} ${startTime}-${endTime}`;
  }
  return `${startDay} ${startTime} -> ${endDay} ${endTime}`;
}

function extractName(candidate: unknown) {
  if (!candidate) return "";
  if (typeof candidate === "string") return candidate.trim();
  if (typeof candidate === "object") {
    for (const value of Object.values(candidate as Record<string, unknown>)) {
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
  }
  return "";
}

async function resetTable() {
  const existing = await scanAll();
  for (const node of existing.nodes) {
    await deleteEntity(node.id);
  }
  for (const link of existing.links) {
    await deleteConnection(link.id);
  }
}

async function main() {
  if (RESET_TABLE) {
    await resetTable();
  }

  const raw = fs.readFileSync(DATA_PATH, "utf-8");
  const rows = parseFixedWidthTable(raw);
  const now = nowIso();

  const nodes = new Map<string, BaseEntity>();
  const connections = new Map<string, Connection>();

  const ensureNode = (
    type: EntityType,
    name: string,
    extras: Partial<BaseEntity> = {}
  ) => {
    const trimmed = name.trim();
    if (!trimmed) return "";
    const id = makeId(type, trimmed);
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        type,
        name: trimmed,
        createdAt: now,
        updatedAt: now,
        ...extras,
      });
    }
    return id;
  };

  const ensureConnection = (
    type: ConnectionType,
    fromId: string,
    toId: string
  ) => {
    if (!fromId || !toId) return;
    const id = `conn-${type}-${fromId}-${toId}`;
    if (!connections.has(id)) {
      connections.set(id, {
        id,
        type,
        fromId,
        toId,
        createdAt: now,
      });
    }
  };

  for (const row of rows) {
    const number = row.number || row["number"];
    if (!number) continue;
    const startDate = row.start_date || row["start_date"];
    const endDate = row.end_date || row["end_date"];
    const shortDescription =
      row.short_description || row["short_description"];
    const description = row.description || row["description"];
    const divisionRaw = row.Division || row["Division"] || "";
    const aiScoreRaw = row.ai_score || row["ai_score"];
    const riskRaw = row.risk || row["risk"];
    const appJson = row.app_service_trigger_json || row["app_service_trigger_json"];

    const aiScore =
      aiScoreRaw && aiScoreRaw.trim()
        ? Number.parseFloat(aiScoreRaw)
        : null;
    const riskValue = riskRaw ? riskRaw.trim() : "";

    const divisionParts = divisionRaw
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    const divisionName = divisionParts[0] || "";
    const serviceName =
      divisionParts.length > 1 ? divisionParts.slice(1).join(", ") : "";

    const timeWindowLabel = parseTimeWindow(startDate, endDate);

    const changeId = ensureNode("change", number, {
      shortDescription,
      description,
      startDate,
      endDate,
      division: divisionName || undefined,
      service: serviceName || undefined,
      risk: riskValue || undefined,
      aiScore,
      timeWindow: timeWindowLabel || undefined,
    });

    const divisionId = divisionName
      ? ensureNode("division", divisionName)
      : "";
    if (divisionId) ensureConnection("belongs_to", changeId, divisionId);

    const serviceId = serviceName ? ensureNode("service", serviceName) : "";
    if (serviceId) ensureConnection("impacts", changeId, serviceId);

    if (riskValue) {
      const riskId = ensureNode("risk", `Risk ${riskValue}`, {
        attributes: { level: riskValue },
      });
      ensureConnection("rated_as", changeId, riskId);
    }

    if (timeWindowLabel) {
      const timeId = ensureNode("time_window", timeWindowLabel, {
        attributes: { startDate, endDate },
      });
      ensureConnection("scheduled_in", changeId, timeId);
    }

    if (appJson) {
      try {
        const parsed = JSON.parse(appJson);
        const servers = Array.isArray(parsed.Servers) ? parsed.Servers : [];
        for (const server of servers) {
          const rawServer =
            typeof server === "object" && server
              ? (server as Record<string, unknown>)
              : undefined;
          const name = extractName(
            rawServer
              ? rawServer.ServerName || rawServer.serverName || rawServer.name
              : server
          );
          const ip = rawServer
            ? (rawServer.ServerIP || rawServer.serverIP || rawServer.ip || "")
            : "";
          if (!name && !ip) continue;
          const ipValue = typeof ip === "string" ? ip.trim() : "";
          const labelBase = name || ipValue;
          const label = ipValue && name ? `${name} (${ipValue})` : labelBase;
          const serverId = ensureNode("server", label, {
            attributes: ipValue ? { ip: ipValue } : undefined,
          });
          ensureConnection("touches", changeId, serverId);
          if (ipValue) {
            const ipId = ensureNode("ip", ipValue, {
              attributes: { ip: ipValue },
            });
            ensureConnection("uses_ip", serverId, ipId);
          }
        }

        const apps = Array.isArray(parsed.ConnectedApplications)
          ? parsed.ConnectedApplications
          : [];
        for (const app of apps) {
          const rawApp =
            typeof app === "object" && app ? (app as Record<string, unknown>) : undefined;
          const appName = extractName(
            rawApp
              ? rawApp.ApplicationName || rawApp.applicationName || rawApp.name
              : app
          );
          const apm = rawApp ? rawApp.ApplicationAPM || rawApp.apm || rawApp.id : "";
          if (!appName && !apm) continue;
          const label = appName || String(apm);
          const appId = ensureNode("application", label, {
            attributes: apm ? { apm } : undefined,
          });
          ensureConnection("affects", changeId, appId);
        }

        const capabilities = Array.isArray(parsed.BusinessCapabilities)
          ? parsed.BusinessCapabilities
          : [];
        for (const capability of capabilities) {
          const capName = extractName(capability);
          if (!capName) continue;
          const capId = ensureNode("capability", capName);
          ensureConnection("depends_on", changeId, capId);
        }
      } catch {
        // Ignore invalid JSON; data provenance stays the same.
      }
    }
  }

  for (const node of nodes.values()) {
    await putEntity(node);
  }
  for (const link of connections.values()) {
    await putConnection(link);
  }

  await putSchema(defaultSchema);

  console.log(
    `Seeded ${nodes.size} nodes and ${connections.size} connections.`
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

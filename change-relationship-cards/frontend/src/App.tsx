import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import type { BaseEntity, Connection, ConnectionType, EntityType } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:3000";
const COGNITO_DOMAIN = import.meta.env.VITE_COGNITO_DOMAIN || "";
const COGNITO_CLIENT_ID = import.meta.env.VITE_COGNITO_CLIENT_ID || "";
const COGNITO_REDIRECT_URI =
  import.meta.env.VITE_COGNITO_REDIRECT_URI || window.location.origin;

const AUTH_STORAGE_KEY = "change_relationship_auth";

type ViewMode = "cards" | "graph" | "admin";
type AuthState = {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
};

const typeColors: Record<EntityType, string> = {
  change: "#ff7a59",
  division: "#d8a649",
  service: "#ffb347",
  server: "#57bfb5",
  application: "#7ea2ff",
  capability: "#6de36d",
  ip: "#7f8c8d",
  risk: "#ff3b30",
  time_window: "#f4a261",
};

const typeLabels: Record<EntityType, string> = {
  change: "change",
  division: "division",
  service: "service",
  server: "server",
  application: "application",
  capability: "capability",
  ip: "ip",
  risk: "risk",
  time_window: "time window",
};

const graphTypeOrder: EntityType[] = [
  "change",
  "division",
  "service",
  "server",
  "application",
  "capability",
  "ip",
  "risk",
  "time_window",
];

function loadAuth(): AuthState | null {
  const raw = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthState;
  } catch {
    return null;
  }
}

function isExpired(auth: AuthState) {
  return Date.now() > auth.expiresAt - 60_000;
}

function base64UrlEncode(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(input: string) {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(hash);
}

function randomString(length = 64) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const values = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(values, (v) => charset[v % charset.length]).join("");
}

function login() {
  if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID) return;
  const verifier = randomString(64);
  const state = randomString(16);
  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("oauth_state", state);
  sha256(verifier).then((challenge) => {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: COGNITO_CLIENT_ID,
      redirect_uri: COGNITO_REDIRECT_URI,
      scope: "openid profile email",
      state,
      code_challenge_method: "S256",
      code_challenge: challenge,
    });
    window.location.href = `${COGNITO_DOMAIN}/oauth2/authorize?${params.toString()}`;
  });
}

async function exchangeCodeForTokens(
  code: string,
  state: string,
  persist: (value: AuthState | null) => void
) {
  const storedState = sessionStorage.getItem("oauth_state");
  const verifier = sessionStorage.getItem("pkce_verifier");
  if (!verifier || (storedState && storedState !== state)) {
    throw new Error("Invalid state");
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: COGNITO_CLIENT_ID,
    code,
    redirect_uri: COGNITO_REDIRECT_URI,
    code_verifier: verifier,
  });
  const resp = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!resp.ok) throw new Error("Token exchange failed");
  const data = await resp.json();
  persist({
    accessToken: data.access_token,
    idToken: data.id_token,
    refreshToken: data.refresh_token,
    expiresAt: Date.now() + (data.expires_in || 3600) * 1000,
  });
}

async function refreshTokens(auth: AuthState, persist: (value: AuthState | null) => void) {
  if (!auth.refreshToken) return;
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: COGNITO_CLIENT_ID,
    refresh_token: auth.refreshToken,
  });
  const resp = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!resp.ok) throw new Error("Refresh failed");
  const data = await resp.json();
  persist({
    accessToken: data.access_token,
    idToken: data.id_token || auth.idToken,
    refreshToken: auth.refreshToken,
    expiresAt: Date.now() + (data.expires_in || 3600) * 1000,
  });
}

async function getValidAccessToken(
  auth: AuthState | null,
  persist: (value: AuthState | null) => void
) {
  if (!auth) return null;
  if (!isExpired(auth)) return auth.accessToken;
  if (auth.refreshToken && COGNITO_DOMAIN && COGNITO_CLIENT_ID) {
    try {
      await refreshTokens(auth, persist);
      const refreshed = loadAuth();
      return refreshed?.accessToken || null;
    } catch {
      persist(null);
      return null;
    }
  }
  return null;
}

function logout(persist: (value: AuthState | null) => void) {
  persist(null);
  if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID) return;
  const params = new URLSearchParams({
    client_id: COGNITO_CLIENT_ID,
    logout_uri: COGNITO_REDIRECT_URI,
  });
  window.location.href = `${COGNITO_DOMAIN}/logout?${params.toString()}`;
}

function formatList(items: string[], limit = 4) {
  if (!items.length) return "—";
  const shown = items.slice(0, limit);
  const extra = items.length - shown.length;
  return extra > 0 ? `${shown.join(", ")} +${extra}` : shown.join(", ");
}

function formatDate(value?: string) {
  if (!value) return "—";
  const trimmed = value.trim();
  if (!trimmed) return "—";
  const parts = trimmed.split(" ");
  if (parts.length >= 2) {
    return `${parts[0]} ${parts[1].slice(0, 5)}`;
  }
  return trimmed;
}

function truncateText(value: string, max = 180) {
  const cleaned = value.replace(/\s+/g, " ").trim();
  if (!cleaned) return "No description available.";
  if (cleaned.length <= max) return cleaned;
  return `${cleaned.slice(0, max).trimEnd()}...`;
}

function highlightText(text: string, needle: string) {
  if (!needle) return text;
  const lower = text.toLowerCase();
  const search = needle.toLowerCase();
  if (!lower.includes(search)) return text;
  const parts: Array<string | JSX.Element> = [];
  let start = 0;
  let index = lower.indexOf(search, start);
  while (index !== -1) {
    if (index > start) {
      parts.push(text.slice(start, index));
    }
    parts.push(
      <mark key={`${text}-${index}`} className="highlight">
        {text.slice(index, index + search.length)}
      </mark>
    );
    start = index + search.length;
    index = lower.indexOf(search, start);
  }
  if (start < text.length) {
    parts.push(text.slice(start));
  }
  return parts;
}

export default function App() {
  const [view, setView] = useState<ViewMode>("cards");
  const [nodes, setNodes] = useState<BaseEntity[]>([]);
  const [links, setLinks] = useState<Connection[]>([]);
  const [search, setSearch] = useState("");
  const [divisionFilter, setDivisionFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState<string[]>([]);
  const [serverFilter, setServerFilter] = useState("");
  const [timeFilter, setTimeFilter] = useState("");
  const [aiMin, setAiMin] = useState("");
  const [aiMax, setAiMax] = useState("");
  const [selected, setSelected] = useState<BaseEntity | null>(null);
  const [flipped, setFlipped] = useState<Record<string, boolean>>({});
  const [notesDraft, setNotesDraft] = useState("");
  const [communityNotesDraft, setCommunityNotesDraft] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [graphSelected, setGraphSelected] = useState<BaseEntity | null>(null);
  const graphRef = useRef<any>(null);
  const [graphTypeFilters, setGraphTypeFilters] = useState<Record<EntityType, boolean>>(
    () =>
      graphTypeOrder.reduce(
        (acc, type) => ({ ...acc, [type]: true }),
        {} as Record<EntityType, boolean>
      )
  );
  const [auth, setAuth] = useState<AuthState | null>(() => loadAuth());

  function flashStatus(message: string) {
    setStatus(message);
    setTimeout(() => setStatus(null), 2000);
  }

  function persistAuth(value: AuthState | null) {
    setAuth(value);
    if (value) {
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(value));
    } else {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    }
  }

  async function apiFetch(input: string, init: RequestInit = {}, requireAuth = false) {
    const headers = new Headers(init.headers || {});
    if (requireAuth) {
      const token = await getValidAccessToken(auth, persistAuth);
      if (!token) {
        throw new Error("Missing auth token");
      }
      headers.set("Authorization", `Bearer ${token}`);
    }
    return fetch(input, { ...init, headers });
  }

  useEffect(() => {
    if (!COGNITO_DOMAIN || !COGNITO_CLIENT_ID) return;
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (code) {
      exchangeCodeForTokens(code, state || "", persistAuth)
        .catch(() => flashStatus("Login failed."))
        .finally(() => {
          window.history.replaceState({}, document.title, window.location.pathname);
        });
    } else if (auth?.refreshToken && isExpired(auth)) {
      refreshTokens(auth, persistAuth).catch(() => undefined);
    }
  }, []);

  useEffect(() => {
    const fetchGraph = async () => {
      const resp = await apiFetch(`${API_BASE}/graph`, {}, true);
      if (resp.status === 401) {
        flashStatus("Please sign in to view the app.");
        return;
      }
      const data = await resp.json();
      setNodes(data.nodes || []);
      setLinks(data.links || []);
    };
    if (auth?.accessToken) {
      fetchGraph().catch(() => flashStatus("Unable to load data. Check API settings."));
    }
  }, [auth?.accessToken]);

  useEffect(() => {
    if (!selected) return;
    setNotesDraft("");
    setCommunityNotesDraft("");
    const loadNotes = async () => {
      try {
        const [privateResp, communityResp] = await Promise.all([
          apiFetch(`${API_BASE}/notes/${selected.id}`, {}, true),
          apiFetch(`${API_BASE}/community-notes/${selected.id}`, {}, true),
        ]);
        const privateData = await privateResp.json();
        const communityData = await communityResp.json();
        setNotesDraft(privateData.notes || "");
        setCommunityNotesDraft(communityData.notes || "");
      } catch {
        flashStatus("Unable to load notes.");
      }
    };
    loadNotes();
  }, [selected?.id]);

  const entityById = useMemo(() => {
    return new Map(nodes.map((node) => [node.id, node]));
  }, [nodes]);

  const linksByFrom = useMemo(() => {
    const map = new Map<string, Connection[]>();
    links.forEach((link) => {
      const list = map.get(link.fromId) ?? [];
      list.push(link);
      map.set(link.fromId, list);
    });
    return map;
  }, [links]);

  const changes = useMemo(
    () => nodes.filter((node) => node.type === "change"),
    [nodes]
  );

  const divisions = useMemo(
    () => nodes.filter((node) => node.type === "division"),
    [nodes]
  );

  const risks = useMemo(
    () => nodes.filter((node) => node.type === "risk"),
    [nodes]
  );

  const timeWindows = useMemo(
    () => nodes.filter((node) => node.type === "time_window"),
    [nodes]
  );
  const servers = useMemo(
    () => nodes.filter((node) => node.type === "server"),
    [nodes]
  );

  function relatedEntities(id: string, type: ConnectionType) {
    const outgoing = linksByFrom.get(id) ?? [];
    return outgoing
      .filter((link) => link.type === type)
      .map((link) => entityById.get(link.toId))
      .filter(Boolean) as BaseEntity[];
  }

  function getRiskLabel(change: BaseEntity) {
    const riskNode = relatedEntities(change.id, "rated_as")[0];
    if (riskNode?.name) return riskNode.name;
    if (change.risk) return `Risk ${change.risk}`;
    return "Risk unknown";
  }

  function getTimeLabel(change: BaseEntity) {
    const timeNode = relatedEntities(change.id, "scheduled_in")[0];
    return timeNode?.name || change.timeWindow || "Time window TBD";
  }

  function getDivisionLabel(change: BaseEntity) {
    const division = relatedEntities(change.id, "belongs_to")[0];
    return division?.name || change.division || "Division TBD";
  }

  function getServiceLabel(change: BaseEntity) {
    const service = relatedEntities(change.id, "impacts")[0];
    return service?.name || change.service || "";
  }

  const filteredChanges = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const minScore = aiMin.trim() ? Number.parseFloat(aiMin) : null;
    const maxScore = aiMax.trim() ? Number.parseFloat(aiMax) : null;

    return changes
      .filter((change) => {
        const divisionLabel = getDivisionLabel(change).toLowerCase();
        const serviceLabel = getServiceLabel(change).toLowerCase();
        const timeLabel = getTimeLabel(change);
        const riskLabel = getRiskLabel(change);
        const serverNames = relatedEntities(change.id, "touches").map((item) =>
          item.name.toLowerCase()
        );

        const matchesSearch = needle
          ? [
              change.name,
              change.shortDescription,
              change.description,
              divisionLabel,
              serviceLabel,
            ]
              .filter(Boolean)
              .some((value) => String(value).toLowerCase().includes(needle))
          : true;

        const matchesDivision = divisionFilter
          ? divisionLabel === divisionFilter.toLowerCase()
          : true;
        const matchesRisk = riskFilter.length
          ? riskFilter.some(
              (selected) => selected.toLowerCase() === riskLabel.toLowerCase()
            )
          : true;
        const matchesTime = timeFilter ? timeLabel === timeFilter : true;
        const matchesServer = serverFilter
          ? serverNames.includes(serverFilter.toLowerCase())
          : true;

        const score = change.aiScore;
        const matchesMin =
          minScore !== null ? typeof score === "number" && score >= minScore : true;
        const matchesMax =
          maxScore !== null ? typeof score === "number" && score <= maxScore : true;

        return (
          matchesSearch &&
          matchesDivision &&
          matchesRisk &&
          matchesTime &&
          matchesServer &&
          matchesMin &&
          matchesMax
        );
      })
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [
    changes,
    search,
    divisionFilter,
    riskFilter,
    timeFilter,
    serverFilter,
    aiMin,
    aiMax,
    nodes,
    links,
  ]);

  function toggleFlip(id: string) {
    setFlipped((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  async function saveNotes() {
    if (!selected) return;
    try {
      await Promise.all([
        apiFetch(
          `${API_BASE}/notes/${selected.id}`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ notes: notesDraft }),
          },
          true
        ),
        apiFetch(
          `${API_BASE}/community-notes/${selected.id}`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ notes: communityNotesDraft }),
          },
          true
        ),
      ]);
      flashStatus("Notes saved.");
      setSelected(null);
    } catch {
      flashStatus("Save failed.");
    }
  }

  const graphData = useMemo(() => {
    const allowedTypes = graphTypeFilters;
    const changeIds = new Set(filteredChanges.map((change) => change.id));
    const connectedIds = new Set(changeIds);

    links.forEach((link) => {
      if (changeIds.has(link.fromId)) {
        connectedIds.add(link.toId);
      }
      if (changeIds.has(link.toId)) {
        connectedIds.add(link.fromId);
      }
    });

    const allowedNodes = nodes.filter(
      (node) => allowedTypes[node.type] && connectedIds.has(node.id)
    );

    const allowedIds = new Set(allowedNodes.map((node) => node.id));
    const filteredLinks = links.filter(
      (link) => allowedIds.has(link.fromId) && allowedIds.has(link.toId)
    );

    return {
      nodes: allowedNodes.map((node) => ({
        ...node,
        id: node.id,
        label: node.name,
        color: typeColors[node.type],
      })),
      links: filteredLinks.map((link) => ({
        ...link,
        source: link.fromId,
        target: link.toId,
      })),
    };
  }, [nodes, links, graphTypeFilters, filteredChanges]);

  function relatedByType(entity: BaseEntity) {
    const linksFor = links.filter(
      (link) => link.fromId === entity.id || link.toId === entity.id
    );
    const grouped = new Map<EntityType, BaseEntity[]>();
    for (const link of linksFor) {
      const otherId = link.fromId === entity.id ? link.toId : link.fromId;
      const other = entityById.get(otherId);
      if (!other) continue;
      const list = grouped.get(other.type) ?? [];
      list.push(other);
      grouped.set(other.type, list);
    }
    return grouped;
  }

  return (
    <div className="app">
      <header className="hero">
        <div>
          <p className="eyebrow">change relationship cards</p>
          <h1>relationship intelligence, mapped.</h1>
          <p className="subtitle">
            Explore change requests as collectible cards and a force graph that reveals
            how divisions, services, servers, apps, and risk intersect across time windows.
          </p>
        </div>
        <div className="tabs">
          {(["cards", "graph", "admin"] as ViewMode[]).map((mode) => (
            <button
              key={mode}
              className={view === mode ? "tab active" : "tab"}
              onClick={() => setView(mode)}
            >
              {mode}
            </button>
          ))}
          {auth?.accessToken && (
            <button className="tab ghost" onClick={() => logout(persistAuth)}>
              sign out
            </button>
          )}
        </div>
      </header>

      {status && <div className="status">{status}</div>}

      {!auth?.accessToken && COGNITO_DOMAIN && COGNITO_CLIENT_ID ? (
        <section className="auth-gate">
          <div className="auth-card">
            <h2>Sign in required</h2>
            <p>
              This app is protected. Please sign in with your Cognito account to
              access the change relationship graph.
            </p>
            <button onClick={() => login()}>Sign in with Cognito</button>
          </div>
        </section>
      ) : (
        <>
          {view === "cards" && (
            <section className="cards-view">
              <div className="filters">
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search change number, text, division"
                />
                <select
                  value={divisionFilter}
                  onChange={(event) => setDivisionFilter(event.target.value)}
                >
                  <option value="">All divisions</option>
                  {divisions
                    .slice()
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((division) => (
                      <option key={division.id} value={division.name}>
                        {division.name}
                      </option>
                    ))}
                </select>
                <div className="filter-group">
                  <span>Risks</span>
                  {risks
                    .slice()
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((risk) => (
                      <label key={risk.id} className="checkbox">
                        <input
                          type="checkbox"
                          checked={riskFilter.includes(risk.name)}
                          onChange={() =>
                            setRiskFilter((prev) =>
                              prev.includes(risk.name)
                                ? prev.filter((value) => value !== risk.name)
                                : [...prev, risk.name]
                            )
                          }
                        />
                        {risk.name}
                      </label>
                    ))}
                </div>
                <select
                  value={timeFilter}
                  onChange={(event) => setTimeFilter(event.target.value)}
                >
                  <option value="">All time windows</option>
                  {timeWindows
                    .slice()
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((time) => (
                      <option key={time.id} value={time.name}>
                        {time.name}
                      </option>
                    ))}
                </select>
                <select
                  value={serverFilter}
                  onChange={(event) => setServerFilter(event.target.value)}
                >
                  <option value="">All servers</option>
                  {servers
                    .slice()
                    .sort((a, b) => a.name.localeCompare(b.name))
                    .map((server) => (
                      <option key={server.id} value={server.name}>
                        {server.name}
                      </option>
                    ))}
                </select>
                <div className="range-inputs">
                  <input
                    type="number"
                    value={aiMin}
                    onChange={(event) => setAiMin(event.target.value)}
                    placeholder="AI min"
                  />
                  <input
                    type="number"
                    value={aiMax}
                    onChange={(event) => setAiMax(event.target.value)}
                    placeholder="AI max"
                  />
                </div>
              </div>
              <div className="grid">
                {filteredChanges.map((change) => {
                  const divisionLabel = getDivisionLabel(change);
                  const serviceLabel = getServiceLabel(change);
                  const timeLabel = getTimeLabel(change);
                  const riskLabel = getRiskLabel(change);
                  const riskLevelMatch = riskLabel.match(/(\d+)/);
                  const riskLevel = riskLevelMatch ? riskLevelMatch[1] : "";
                  const serverNodes = relatedEntities(change.id, "touches");
                  const servers = serverNodes.map((item) => item.name);
                  const apps = relatedEntities(change.id, "affects").map((item) => item.name);
                  const caps = relatedEntities(change.id, "depends_on").map((item) => item.name);
                  const serverIds = new Set(serverNodes.map((item) => item.id));
                  const ipNames = Array.from(
                    new Set(
                      links
                        .filter(
                          (link) =>
                            link.type === "uses_ip" && serverIds.has(link.fromId)
                        )
                        .map((link) => entityById.get(link.toId)?.name)
                        .filter(Boolean) as string[]
                    )
                  );

                  return (
                    <div
                      key={change.id}
                      className={`card ${flipped[change.id] ? "is-flipped" : ""}`}
                      onClick={() => toggleFlip(change.id)}
                      onDoubleClick={() => setSelected(change)}
                    >
                      <div className="card-inner">
                        <div className="card-face card-front">
                          <div className="card-hero">
                            <div className="card-hero-grid">
                              <div className="card-hero-main">
                                <div className="card-hero-top">
                                  <span className="card-number">
                                    {highlightText(change.name, search)}
                                  </span>
                                  <span
                                    className={`risk-pill ${riskLevel ? `risk-${riskLevel}` : ""}`}
                                  >
                                    {riskLabel}
                                  </span>
                                </div>
                                <h3 className="card-title">
                                  {highlightText(
                                    change.shortDescription || "No summary available",
                                    search
                                  )}
                                </h3>
                                <div className="card-subtitle">
                                  <span>{highlightText(divisionLabel, search)}</span>
                                  {serviceLabel && (
                                    <span>{highlightText(serviceLabel, search)}</span>
                                  )}
                                </div>
                                <div className="card-chip-row">
                                  <span className="chip">
                                    Start: {formatDate(change.startDate)}
                                  </span>
                                  <span className="chip">
                                    End: {formatDate(change.endDate)}
                                  </span>
                                  <span className="chip">
                                    AI score:{" "}
                                    {typeof change.aiScore === "number" ? change.aiScore : "—"}
                                  </span>
                                  <span className="chip">Servers: {servers.length}</span>
                                  <span className="chip">Apps: {apps.length}</span>
                                </div>
                              </div>
                            </div>
                            <div className="card-hero-actions">
                              <button
                                className="sage-button"
                                type="button"
                                onClick={(event) => event.stopPropagation()}
                              >
                                <span className="sage-icon" aria-hidden>
                                  <svg
                                    viewBox="0 0 24 24"
                                    width="16"
                                    height="16"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                  >
                                    <circle
                                      cx="12"
                                      cy="12"
                                      r="10.5"
                                      stroke="currentColor"
                                      strokeWidth="1.4"
                                    />
                                    <path
                                      d="M8.4 9.5c.8-.8 2-1.3 3.6-1.3 1.6 0 2.8.5 3.6 1.3"
                                      stroke="currentColor"
                                      strokeWidth="1.4"
                                      strokeLinecap="round"
                                    />
                                    <circle cx="9.5" cy="12" r="1" fill="currentColor" />
                                    <circle cx="14.5" cy="12" r="1" fill="currentColor" />
                                    <path
                                      d="M8 15.2c1.2 1.1 2.6 1.6 4 1.6 1.4 0 2.8-.5 4-1.6"
                                      stroke="currentColor"
                                      strokeWidth="1.4"
                                      strokeLinecap="round"
                                    />
                                  </svg>
                                </span>
                                Chat with Sage
                              </button>
                              <button
                                className="ghost-button"
                                type="button"
                                onClick={(event) => event.stopPropagation()}
                              >
                                Analyze change
                              </button>
                            </div>
                            <div className="sage-fab" aria-hidden>
                              <svg
                                viewBox="0 0 24 24"
                                width="20"
                                height="20"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <circle
                                  cx="12"
                                  cy="12"
                                  r="10.5"
                                  stroke="currentColor"
                                  strokeWidth="1.4"
                                />
                                <path
                                  d="M8.4 9.5c.8-.8 2-1.3 3.6-1.3 1.6 0 2.8.5 3.6 1.3"
                                  stroke="currentColor"
                                  strokeWidth="1.4"
                                  strokeLinecap="round"
                                />
                                <circle cx="9.5" cy="12" r="1" fill="currentColor" />
                                <circle cx="14.5" cy="12" r="1" fill="currentColor" />
                                <path
                                  d="M8 15.2c1.2 1.1 2.6 1.6 4 1.6 1.4 0 2.8-.5 4-1.6"
                                  stroke="currentColor"
                                  strokeWidth="1.4"
                                  strokeLinecap="round"
                                />
                              </svg>
                            </div>
                          </div>
                          <div className="card-body">
                            <div className="card-summary">
                              <span>Summary</span>
                              <p>
                                {highlightText(
                                  truncateText(
                                    change.description || change.shortDescription || ""
                                  ),
                                  search
                                )}
                              </p>
                            </div>
                            <div className="card-index">
                              <div className="card-index-title">Key relationships</div>
                              <div className="card-index-grid">
                                <div>
                                  <span>Division</span>
                                  <strong>{highlightText(divisionLabel, search)}</strong>
                                </div>
                                <div>
                                  <span>Service</span>
                                  <strong>
                                    {highlightText(serviceLabel || "—", search)}
                                  </strong>
                                </div>
                                <div>
                                  <span>Risk</span>
                                  <strong>{highlightText(riskLabel, search)}</strong>
                                </div>
                                <div>
                                  <span>Time window</span>
                                  <strong>{highlightText(timeLabel, search)}</strong>
                                </div>
                                <div>
                                  <span>Servers</span>
                                  <strong>
                                    {highlightText(formatList(servers, 2), search)}
                                  </strong>
                                </div>
                                <div>
                                  <span>IPs</span>
                                  <strong>
                                    {highlightText(formatList(ipNames, 2), search)}
                                  </strong>
                                </div>
                                <div>
                                  <span>Applications</span>
                                  <strong>
                                    {highlightText(formatList(apps, 2), search)}
                                  </strong>
                                </div>
                                <div>
                                  <span>Capabilities</span>
                                  <strong>
                                    {highlightText(formatList(caps, 2), search)}
                                  </strong>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                        <div className="card-face card-back">
                          <div className="card-back-header">
                            <h3>{change.name}</h3>
                            <span>{divisionLabel}</span>
                          </div>
                          <div className="card-bio" onClick={(event) => event.stopPropagation()}>
                            <p>{change.description || "No description available."}</p>
                            <div className="card-meta">
                              <div>Servers: {formatList(servers)}</div>
                              <div>Applications: {formatList(apps)}</div>
                              <div>Capabilities: {formatList(caps)}</div>
                            </div>
                          </div>
                          <button
                            className="card-edit"
                            onClick={(event) => {
                              event.stopPropagation();
                              setSelected(change);
                            }}
                          >
                            Open details
                          </button>
                          <div className="card-hint">Double-click for details</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {view === "graph" && (
            <section className="graph-view">
              <div className="graph-filters">
                <div className="filters">
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search change number, text, division"
                  />
                  <select
                    value={divisionFilter}
                    onChange={(event) => setDivisionFilter(event.target.value)}
                  >
                    <option value="">All divisions</option>
                    {divisions
                      .slice()
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .map((division) => (
                        <option key={division.id} value={division.name}>
                          {division.name}
                        </option>
                      ))}
                  </select>
                  <div className="filter-group">
                    <span>Risks</span>
                    {risks
                      .slice()
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .map((risk) => (
                        <label key={risk.id} className="checkbox">
                          <input
                            type="checkbox"
                            checked={riskFilter.includes(risk.name)}
                            onChange={() =>
                              setRiskFilter((prev) =>
                                prev.includes(risk.name)
                                  ? prev.filter((value) => value !== risk.name)
                                  : [...prev, risk.name]
                              )
                            }
                          />
                          {risk.name}
                        </label>
                      ))}
                  </div>
                  <select
                    value={timeFilter}
                    onChange={(event) => setTimeFilter(event.target.value)}
                  >
                    <option value="">All time windows</option>
                    {timeWindows
                      .slice()
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .map((time) => (
                        <option key={time.id} value={time.name}>
                          {time.name}
                        </option>
                      ))}
                  </select>
                  <select
                    value={serverFilter}
                    onChange={(event) => setServerFilter(event.target.value)}
                  >
                    <option value="">All servers</option>
                    {servers
                      .slice()
                      .sort((a, b) => a.name.localeCompare(b.name))
                      .map((server) => (
                        <option key={server.id} value={server.name}>
                          {server.name}
                        </option>
                      ))}
                  </select>
                  <div className="range-inputs">
                    <input
                      type="number"
                      value={aiMin}
                      onChange={(event) => setAiMin(event.target.value)}
                      placeholder="AI min"
                    />
                    <input
                      type="number"
                      value={aiMax}
                      onChange={(event) => setAiMax(event.target.value)}
                      placeholder="AI max"
                    />
                  </div>
                </div>
                <div className="filter-group">
                  <span>Show</span>
                  {graphTypeOrder.map((type) => (
                    <label key={type} className="checkbox">
                      <input
                        type="checkbox"
                        checked={graphTypeFilters[type]}
                        onChange={() =>
                          setGraphTypeFilters((prev) => ({
                            ...prev,
                            [type]: !prev[type],
                          }))
                        }
                      />
                      {typeLabels[type] ?? type}
                    </label>
                  ))}
                </div>
              </div>
              <div className="graph-layout">
                <div className="graph-panel">
                  <ForceGraph2D
                    ref={graphRef}
                    graphData={graphData}
                    nodeLabel={(node: any) =>
                      node.type === "change"
                        ? `${node.label} - ${node.shortDescription || "Change"}`
                        : `${node.label} (${typeLabels[node.type]})`
                    }
                    nodeColor={(node: any) => node.color}
                    linkLabel={(link: any) => link.type}
                    linkColor={() => "rgba(17,17,17,0.2)"}
                    linkDirectionalParticles={1}
                    linkDirectionalParticleWidth={1}
                    linkDirectionalArrowLength={8}
                    linkDirectionalArrowRelPos={1}
                    linkDirectionalArrowColor={() => "rgba(251,100,0,0.8)"}
                    nodeCanvasObject={(node: any, ctx, globalScale) => {
                      const label = node.label;
                      const size =
                        node.type === "risk"
                          ? 26
                          : node.type === "change"
                            ? 20
                            : node.type === "division"
                              ? 13
                              : 10;
                      const fontSize = 13 / globalScale;
                      ctx.fillStyle = node.color;
                      ctx.beginPath();
                      ctx.arc(node.x, node.y, size, 0, 2 * Math.PI, false);
                      ctx.fill();
                      ctx.strokeStyle = "rgba(255,255,255,0.7)";
                      ctx.lineWidth = 2 / globalScale;
                      ctx.stroke();
                      ctx.font = `${fontSize}px IBM Plex Mono`;
                      ctx.fillStyle = "rgba(17,17,17,0.7)";
                      ctx.textAlign = "center";
                      ctx.fillText(label, node.x, node.y + size + 12 / globalScale);
                    }}
                    onNodeClick={(node: any) => {
                      const entity = nodes.find((item) => item.id === node.id);
                      if (!entity) return;
                      setGraphSelected(entity);
                    }}
                    onNodeDoubleClick={(node: any) => {
                      const entity = nodes.find((item) => item.id === node.id);
                      if (!entity) return;
                      setSelected(entity);
                      setView("cards");
                    }}
                  />
                </div>
                <aside className="graph-sidebar">
                  <div className="legend">
                    <strong>Legend</strong>
                    <ul>
                      {graphTypeOrder.map((type) => (
                        <li key={type}>
                          <span style={{ background: typeColors[type] }} />
                          {typeLabels[type]}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="graph-detail">
                    {graphSelected ? (
                      <>
                        <h3>{graphSelected.name}</h3>
                        <p>{typeLabels[graphSelected.type]}</p>
                        {graphSelected.type === "change" ? (
                          <>
                            <p>{graphSelected.shortDescription || "No summary available."}</p>
                            <p>{getTimeLabel(graphSelected)}</p>
                            <p>{getRiskLabel(graphSelected)}</p>
                          </>
                        ) : (
                          <p>{graphSelected.description || "No description available."}</p>
                        )}
                        <div className="graph-actions">
                          <button
                            onClick={() => {
                              setSelected(graphSelected);
                              setView("cards");
                            }}
                          >
                            open in cards
                          </button>
                          <button
                            onClick={() => {
                              if (!graphRef.current || !graphSelected) return;
                              const node = graphData.nodes.find(
                                (item: any) => item.id === graphSelected.id
                              );
                              if (node && typeof node.x === "number" && typeof node.y === "number") {
                                graphRef.current.centerAt(node.x, node.y, 800);
                                graphRef.current.zoom(3, 800);
                              }
                            }}
                          >
                            focus node
                          </button>
                        </div>
                        {Array.from(relatedByType(graphSelected).entries()).map(
                          ([type, items]) => (
                            <div key={type}>
                              <p>{typeLabels[type]}</p>
                              <div className="pill-list">
                                {items.slice(0, 6).map((item) => (
                                  <span key={item.id} className="pill">
                                    {item.name}
                                  </span>
                                ))}
                                {items.length > 6 && (
                                  <span className="pill">+{items.length - 6}</span>
                                )}
                              </div>
                            </div>
                          )
                        )}
                      </>
                    ) : (
                      <>
                        <h3>Graph explorer</h3>
                        <p>Click any node to inspect its relationships.</p>
                      </>
                    )}
                  </div>
                </aside>
              </div>
            </section>
          )}

          {view === "admin" && (
            <section className="admin-view">
              <div className="admin-panel">
                <h2>Admin access</h2>
                <div className="form">
                  <div className="auth-actions">
                    {auth?.accessToken ? (
                      <>
                        <div className="auth-status">Signed in</div>
                        <button onClick={() => logout(persistAuth)} className="secondary">
                          Sign out
                        </button>
                      </>
                    ) : (
                      <>
                        <div className="auth-status">
                          {COGNITO_DOMAIN && COGNITO_CLIENT_ID
                            ? "Not signed in"
                            : "Cognito not configured"}
                        </div>
                        <button
                          onClick={() => login()}
                          disabled={!COGNITO_DOMAIN || !COGNITO_CLIENT_ID}
                        >
                          Sign in with Cognito
                        </button>
                      </>
                    )}
                  </div>
                  <label>
                    Manual access token (optional)
                    <input
                      value={auth?.accessToken || ""}
                      onChange={(event) =>
                        persistAuth({
                          accessToken: event.target.value,
                          idToken: auth?.idToken || "",
                          refreshToken: auth?.refreshToken,
                          expiresAt: Date.now() + 1000 * 60 * 60,
                        })
                      }
                      placeholder="Paste JWT access token"
                    />
                  </label>
                </div>
              </div>
              <div className="admin-panel template-editor">
                <h2>Template schema</h2>
                <TemplateEditor apiFetch={apiFetch} />
              </div>
              <div className="admin-panel">
                <h2>Create entity</h2>
                <AdminEntityForm
                  apiFetch={apiFetch}
                  onStatus={flashStatus}
                  onCreated={(entity) => setNodes((prev) => [...prev, entity])}
                />
              </div>
              <div className="admin-panel">
                <h2>Edit entity</h2>
                <AdminEditForm
                  nodes={nodes}
                  apiFetch={apiFetch}
                  onStatus={flashStatus}
                  onUpdated={(entity) =>
                    setNodes((prev) => prev.map((node) => (node.id === entity.id ? entity : node)))
                  }
                />
              </div>
              <div className="admin-panel">
                <h2>Create connection</h2>
                <AdminConnectionForm
                  apiFetch={apiFetch}
                  onStatus={flashStatus}
                  nodes={nodes}
                  onCreated={(conn) => setLinks((prev) => [...prev, conn])}
                />
              </div>
              <div className="admin-panel">
                <h2>Delete entity</h2>
                <AdminDeleteForm
                  label="Entity"
                  endpoint="items"
                  apiFetch={apiFetch}
                  onStatus={flashStatus}
                  options={nodes
                    .map((node) => ({
                      id: node.id,
                      label: `${node.name} (${node.type})`,
                    }))
                    .sort((a, b) => a.label.localeCompare(b.label))}
                  onDeleted={(id) => setNodes((prev) => prev.filter((node) => node.id !== id))}
                />
              </div>
              <div className="admin-panel">
                <h2>Delete connection</h2>
                <AdminDeleteForm
                  label="Connection"
                  endpoint="connections"
                  apiFetch={apiFetch}
                  onStatus={flashStatus}
                  options={links
                    .map((conn) => ({
                      id: conn.id,
                      label: `${entityById.get(conn.fromId)?.name ?? conn.fromId} -> ${
                        entityById.get(conn.toId)?.name ?? conn.toId
                      } (${conn.type})`,
                    }))
                    .sort((a, b) => a.label.localeCompare(b.label))}
                  onDeleted={(id) => setLinks((prev) => prev.filter((conn) => conn.id !== id))}
                />
              </div>
            </section>
          )}

          {selected && (
            <div className="drawer">
              <div className="drawer-header">
                <div>
                  <h2>{selected.name}</h2>
                  <p>{typeLabels[selected.type]}</p>
                </div>
                <button className="close" onClick={() => setSelected(null)}>
                  Close
                </button>
              </div>
              <div className="drawer-body">
                <div className="drawer-badge">{typeLabels[selected.type]}</div>
                <div className="drawer-details">
                  {selected.type === "change" ? (
                    <>
                      <div className="detail-row">
                        <span>Division</span>
                        <strong>{getDivisionLabel(selected)}</strong>
                      </div>
                      <div className="detail-row">
                        <span>Service</span>
                        <strong>{getServiceLabel(selected) || "—"}</strong>
                      </div>
                      <div className="detail-row">
                        <span>Time window</span>
                        <strong>{getTimeLabel(selected)}</strong>
                      </div>
                      <div className="detail-row">
                        <span>Risk</span>
                        <strong>{getRiskLabel(selected)}</strong>
                      </div>
                      <div className="detail-row">
                        <span>AI score</span>
                        <strong>
                          {typeof selected.aiScore === "number" ? selected.aiScore : "—"}
                        </strong>
                      </div>
                      <div className="detail-row bio-row">
                        <span>Description</span>
                        <strong>{selected.description || "No description available."}</strong>
                      </div>
                      <details className="detail-expand">
                        <summary>Related servers</summary>
                        <p>
                          {formatList(
                            relatedEntities(selected.id, "touches").map((item) => item.name),
                            8
                          )}
                        </p>
                      </details>
                      <details className="detail-expand">
                        <summary>Related applications</summary>
                        <p>
                          {formatList(
                            relatedEntities(selected.id, "affects").map((item) => item.name),
                            8
                          )}
                        </p>
                      </details>
                      <details className="detail-expand">
                        <summary>Business capabilities</summary>
                        <p>
                          {formatList(
                            relatedEntities(selected.id, "depends_on").map((item) => item.name),
                            8
                          )}
                        </p>
                      </details>
                    </>
                  ) : (
                    <>
                      <div className="detail-row">
                        <span>Type</span>
                        <strong>{typeLabels[selected.type]}</strong>
                      </div>
                      <div className="detail-row bio-row">
                        <span>Description</span>
                        <strong>{selected.description || "No description available."}</strong>
                      </div>
                      {Array.from(relatedByType(selected).entries()).map(([type, items]) => (
                        <details key={type} className="detail-expand">
                          <summary>{typeLabels[type]}</summary>
                          <p>{formatList(items.map((item) => item.name), 8)}</p>
                        </details>
                      ))}
                    </>
                  )}
                  <div className="notes-heading">Private notes</div>
                  <textarea
                    value={notesDraft}
                    onChange={(event) => setNotesDraft(event.target.value)}
                    placeholder="Add private notes"
                  />
                  <div className="notes-heading">Shared notes</div>
                  <textarea
                    value={communityNotesDraft}
                    onChange={(event) => setCommunityNotesDraft(event.target.value)}
                    placeholder="Add shared notes for the team"
                  />
                </div>
              </div>
              <div className="drawer-actions">
                <button className="secondary" onClick={() => setSelected(null)}>
                  Close
                </button>
                <button onClick={() => saveNotes().catch(() => flashStatus("Save failed."))}>
                  Save notes
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function AdminEntityForm({
  onCreated,
  apiFetch,
  onStatus,
}: {
  onCreated: (entity: BaseEntity) => void;
  apiFetch: (input: string, init?: RequestInit, requireAuth?: boolean) => Promise<Response>;
  onStatus?: (message: string) => void;
}) {
  const [type, setType] = useState<EntityType>("change");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [shortDescription, setShortDescription] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [risk, setRisk] = useState("");
  const [aiScore, setAiScore] = useState("");
  const [timeWindow, setTimeWindow] = useState("");
  const [attributes, setAttributes] = useState("{}");

  async function submit() {
    try {
      const parsedAttributes = attributes.trim() ? JSON.parse(attributes) : undefined;
      const resp = await apiFetch(
        `${API_BASE}/items`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            type,
            name,
            description,
            shortDescription: type === "change" ? shortDescription : undefined,
            startDate: type === "change" ? startDate : undefined,
            endDate: type === "change" ? endDate : undefined,
            risk: type === "change" ? risk : undefined,
            aiScore: type === "change" && aiScore ? Number.parseFloat(aiScore) : undefined,
            timeWindow: type === "change" ? timeWindow : undefined,
            attributes: parsedAttributes,
          }),
        },
        true
      );
      if (!resp.ok) throw new Error("create failed");
      const data = await resp.json();
      onCreated(data);
      setName("");
      setDescription("");
      setShortDescription("");
      setStartDate("");
      setEndDate("");
      setRisk("");
      setAiScore("");
      setTimeWindow("");
      setAttributes("{}");
      onStatus?.("Entity created.");
    } catch {
      onStatus?.("Create failed. Check JSON input.");
    }
  }

  return (
    <div className="form">
      <label>
        Type
        <select value={type} onChange={(event) => setType(event.target.value as EntityType)}>
          {graphTypeOrder.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
      <label>
        Name
        <input value={name} onChange={(event) => setName(event.target.value)} />
      </label>
      <label>
        Description
        <textarea value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      {type === "change" && (
        <>
          <label>
            Short description
            <textarea
              value={shortDescription}
              onChange={(event) => setShortDescription(event.target.value)}
            />
          </label>
          <label>
            Start date
            <input value={startDate} onChange={(event) => setStartDate(event.target.value)} />
          </label>
          <label>
            End date
            <input value={endDate} onChange={(event) => setEndDate(event.target.value)} />
          </label>
          <label>
            Risk
            <input value={risk} onChange={(event) => setRisk(event.target.value)} />
          </label>
          <label>
            AI score
            <input value={aiScore} onChange={(event) => setAiScore(event.target.value)} />
          </label>
          <label>
            Time window
            <input value={timeWindow} onChange={(event) => setTimeWindow(event.target.value)} />
          </label>
        </>
      )}
      <label>
        Attributes (JSON)
        <textarea value={attributes} onChange={(event) => setAttributes(event.target.value)} />
      </label>
      <button onClick={() => submit().catch(() => undefined)}>Create</button>
    </div>
  );
}

function AdminConnectionForm({
  onCreated,
  apiFetch,
  onStatus,
  nodes,
}: {
  onCreated: (conn: Connection) => void;
  apiFetch: (input: string, init?: RequestInit, requireAuth?: boolean) => Promise<Response>;
  onStatus?: (message: string) => void;
  nodes: BaseEntity[];
}) {
  const [type, setType] = useState<ConnectionType>("belongs_to");
  const [fromId, setFromId] = useState("");
  const [toId, setToId] = useState("");
  const [filterText, setFilterText] = useState("");
  const entityOptions = useMemo(
    () =>
      nodes
        .map((node) => ({
          id: node.id,
          label: `${node.name} (${node.type})`,
        }))
        .sort((a, b) => a.label.localeCompare(b.label)),
    [nodes]
  );
  const filteredOptions = useMemo(() => {
    const needle = filterText.trim().toLowerCase();
    if (!needle) return entityOptions;
    return entityOptions.filter((option) => option.label.toLowerCase().includes(needle));
  }, [entityOptions, filterText]);

  async function submit() {
    try {
      const resp = await apiFetch(
        `${API_BASE}/connections`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type, fromId, toId }),
        },
        true
      );
      if (!resp.ok) throw new Error("create failed");
      const data = await resp.json();
      onCreated(data);
      setFromId("");
      setToId("");
      onStatus?.("Connection created.");
    } catch {
      onStatus?.("Create failed.");
    }
  }

  return (
    <div className="form">
      <label>
        Type
        <select value={type} onChange={(event) => setType(event.target.value as ConnectionType)}>
          {[
            "belongs_to",
            "impacts",
            "touches",
            "affects",
            "depends_on",
            "rated_as",
            "scheduled_in",
          ].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </label>
      <label>
        Search entities
        <input
          value={filterText}
          onChange={(event) => setFilterText(event.target.value)}
          placeholder="Filter by name or type"
        />
      </label>
      <label>
        From
        <select value={fromId} onChange={(event) => setFromId(event.target.value)}>
          <option value="">Select source</option>
          {filteredOptions.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        To
        <select value={toId} onChange={(event) => setToId(event.target.value)}>
          <option value="">Select target</option>
          {filteredOptions.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <button onClick={() => submit().catch(() => undefined)} disabled={!fromId || !toId}>
        Create
      </button>
    </div>
  );
}

function AdminDeleteForm({
  label,
  endpoint,
  apiFetch,
  onDeleted,
  options,
  onStatus,
}: {
  label: string;
  endpoint: "items" | "connections";
  apiFetch: (input: string, init?: RequestInit, requireAuth?: boolean) => Promise<Response>;
  onDeleted: (id: string) => void;
  options: { id: string; label: string }[];
  onStatus?: (message: string) => void;
}) {
  const [value, setValue] = useState("");
  const [filterText, setFilterText] = useState("");
  const filteredOptions = useMemo(() => {
    const needle = filterText.trim().toLowerCase();
    if (!needle) return options;
    return options.filter((option) => option.label.toLowerCase().includes(needle));
  }, [options, filterText]);

  async function submit() {
    if (!value) return;
    try {
      const resp = await apiFetch(`${API_BASE}/${endpoint}/${value}`, { method: "DELETE" }, true);
      if (!resp.ok) throw new Error("delete failed");
      onDeleted(value);
      setValue("");
      onStatus?.("Deleted.");
    } catch {
      onStatus?.("Delete failed.");
    }
  }

  return (
    <div className="form">
      <label>
        Search {label.toLowerCase()}
        <input
          value={filterText}
          onChange={(event) => setFilterText(event.target.value)}
          placeholder="Filter by name or type"
        />
      </label>
      <label>
        {label}
        <select value={value} onChange={(event) => setValue(event.target.value)}>
          <option value="">Select {label.toLowerCase()}</option>
          {filteredOptions.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <button onClick={() => submit().catch(() => undefined)} disabled={!value}>
        Delete
      </button>
    </div>
  );
}

function AdminEditForm({
  nodes,
  apiFetch,
  onUpdated,
  onStatus,
}: {
  nodes: BaseEntity[];
  apiFetch: (input: string, init?: RequestInit, requireAuth?: boolean) => Promise<Response>;
  onUpdated: (entity: BaseEntity) => void;
  onStatus?: (message: string) => void;
}) {
  const [selectedId, setSelectedId] = useState(nodes[0]?.id || "");
  const selected = nodes.find((node) => node.id === selectedId);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [shortDescription, setShortDescription] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [risk, setRisk] = useState("");
  const [aiScore, setAiScore] = useState("");
  const [timeWindow, setTimeWindow] = useState("");
  const [notes, setNotes] = useState("");
  const [attributes, setAttributes] = useState("{}");

  useEffect(() => {
    if (!selected) return;
    setName(selected.name || "");
    setDescription(selected.description || "");
    setShortDescription(selected.shortDescription || "");
    setStartDate(selected.startDate || "");
    setEndDate(selected.endDate || "");
    setRisk(selected.risk || "");
    setAiScore(typeof selected.aiScore === "number" ? String(selected.aiScore) : "");
    setTimeWindow(selected.timeWindow || "");
    setNotes(selected.notes || "");
    setAttributes(JSON.stringify(selected.attributes || {}, null, 2));
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId && nodes.length) {
      setSelectedId(nodes[0].id);
    }
  }, [nodes, selectedId]);

  async function submit() {
    if (!selected) return;
    try {
      const parsedAttributes = attributes.trim() ? JSON.parse(attributes) : undefined;
      const resp = await apiFetch(
        `${API_BASE}/items/${selected.id}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name,
            description,
            shortDescription: selected.type === "change" ? shortDescription : undefined,
            startDate: selected.type === "change" ? startDate : undefined,
            endDate: selected.type === "change" ? endDate : undefined,
            risk: selected.type === "change" ? risk : undefined,
            aiScore:
              selected.type === "change" && aiScore ? Number.parseFloat(aiScore) : undefined,
            timeWindow: selected.type === "change" ? timeWindow : undefined,
            notes,
            attributes: parsedAttributes,
          }),
        },
        true
      );
      if (!resp.ok) throw new Error("save failed");
      const data = await resp.json();
      onUpdated(data);
      onStatus?.("Entity saved.");
    } catch {
      onStatus?.("Save failed.");
    }
  }

  return (
    <div className="form">
      <label>
        Entity
        <select value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>
          {nodes.map((node) => (
            <option key={node.id} value={node.id}>
              {node.type}: {node.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Name
        <input value={name} onChange={(event) => setName(event.target.value)} />
      </label>
      <label>
        Description
        <textarea value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      {selected?.type === "change" && (
        <>
          <label>
            Short description
            <textarea
              value={shortDescription}
              onChange={(event) => setShortDescription(event.target.value)}
            />
          </label>
          <label>
            Start date
            <input value={startDate} onChange={(event) => setStartDate(event.target.value)} />
          </label>
          <label>
            End date
            <input value={endDate} onChange={(event) => setEndDate(event.target.value)} />
          </label>
          <label>
            Risk
            <input value={risk} onChange={(event) => setRisk(event.target.value)} />
          </label>
          <label>
            AI score
            <input value={aiScore} onChange={(event) => setAiScore(event.target.value)} />
          </label>
          <label>
            Time window
            <input value={timeWindow} onChange={(event) => setTimeWindow(event.target.value)} />
          </label>
        </>
      )}
      <label>
        Notes
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)} />
      </label>
      <label>
        Attributes (JSON)
        <textarea value={attributes} onChange={(event) => setAttributes(event.target.value)} />
      </label>
      <button onClick={() => submit().catch(() => undefined)}>Save</button>
    </div>
  );
}

function TemplateEditor({
  apiFetch,
}: {
  apiFetch: (input: string, init?: RequestInit, requireAuth?: boolean) => Promise<Response>;
}) {
  const [value, setValue] = useState(
    JSON.stringify(
      {
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
      },
      null,
      2
    )
  );
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    apiFetch(`${API_BASE}/schema`, {}, true)
      .then((resp) => resp.json())
      .then((data) => {
        if (data && Object.keys(data).length) {
          setValue(JSON.stringify(data, null, 2));
        }
      })
      .catch(() => undefined);
  }, []);

  function downloadJson() {
    const blob = new Blob([value], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "template.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="form">
      <label>
        JSON template
        <textarea value={value} onChange={(event) => setValue(event.target.value)} />
      </label>
      {status && <div className="status">{status}</div>}
      <button
        onClick={() => {
          apiFetch(
            `${API_BASE}/schema`,
            {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: value,
            },
            true
          )
            .then(() => setStatus("Schema saved."))
            .catch(() => setStatus("Schema save failed."));
        }}
      >
        Save schema
      </button>
      <button onClick={downloadJson}>Download JSON</button>
    </div>
  );
}

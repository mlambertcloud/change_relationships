# Codex Prompt: Change Relationships Graph Cards

You are Codex. Build a **new** full-stack app (separate repo) that reuses the **EMEA SLT Sports Cards** visual style (colors, typography, layout), but the domain is **“changes”** and the focus is **relationship intelligence** and **graph exploration**. This app does **not** need photos.

## Theme + Product Goal
- Theme: **“Change Relationship Cards”** — a collectible-style view of change requests and their connections.
- Goal: **Understand how changes relate** across divisions, services, servers, applications, business capabilities, risk, and time windows.
- Primary view: **GraphDB-style force graph** with filters and drill-down.
- Secondary view: **Card grid** with flip behavior (front summary / back details).
- Admin features: **create/edit/delete nodes and connections**, **template/schema editor**, **notes**, **manual relationship adjustments**.

## Data Source (authoritative)
- Use **only** the data in `data/changes_tomorrow.txt`.
- The file is a **pipe-delimited table** with a header row:
  - `number`, `start_date`, `end_date`, `short_description`, `description`, `Division`, `ai_score`, `risk`, `app_service_trigger_json`
- Do not invent change records. Every node and relationship must be derived from the file.

## Core UX Requirements
- **Cards view**:
  - Search by change number, text, division.
  - Filters by: Division, Risk, Date window, AI score ranges.
  - Card front: change number, short description, time window, division, risk.
  - Card back: full description, related servers/apps/capabilities, structured fields.
  - Flip interaction on click; double-click opens detail drawer.
- **Graph view (very important)**:
  - Force-layout graph showing changes → divisions → services → servers → apps → capabilities → time windows.
  - Legend + type filters (toggle node types).
  - Node click shows a side detail panel with relationships and quick actions.
  - Double-click on a node jumps to cards view and opens that node’s details.
  - Must feel like a **GraphDB explorer**.
- **Admin console**:
  - Entity CRUD
  - Connection CRUD
  - Template/Schema editor (JSON)
  - Notes field per entity (private + shared)

## Visual System (match existing SLT Sports Cards)
- Same **colors**, **type choices**, **spacing**, **card layout**, and **graph styling**.
- Same general structure: tabs for Cards / Graph / Admin.
- No photos anywhere. Use icon placeholders or badges only.

## Domain Model (new app)
Use lowercase entity types:
- `change` (each change record)
- `division` (from the `Division` column, split on comma)
- `service` (optional; extract from `Division` second segment or from descriptions if clearly present)
- `server` (from `app_service_trigger_json.Servers`)
- `application` (from `app_service_trigger_json.ConnectedApplications`)
- `capability` (from `app_service_trigger_json.BusinessCapabilities`)
- `risk` (derived from `risk` column)
- `time_window` (start/end bucket, e.g. `2026-02-26 00:00–04:00`)

Relationships:
- change → division (`belongs_to`)
- change → service (`impacts`)
- change → server (`touches`)
- change → application (`affects`)
- change → capability (`depends_on`)
- change → risk (`rated_as`)
- change → time_window (`scheduled_in`)

## Data Parsing Guidance
- `Division` column can contain multiple values separated by comma.
  - Split into `division` (first segment) and `service` (second segment) when present.
- `app_service_trigger_json` is JSON and may be empty:
  - Parse and expand nodes/links for Servers, ConnectedApplications, BusinessCapabilities.
- `ai_score` can be missing. Store as number or null.
- Risk is numeric; store as string or number consistently.

## Required Features (parity with SLT app)
- Filtered list view with search by change number.
- Detail drawer with notes (private + shared).
- Graph view with legend, selectable nodes, and type filters.
- Admin console with template editor, create/delete entity, create/delete connection.
- Seed script that parses `changes_tomorrow.txt` and creates entities/relationships.

## Technical Stack (match existing repo)
- **Frontend:** React + TypeScript + Vite.
- **Backend:** AWS Lambda (Node 20), API Gateway HTTP API.
- **Data:** DynamoDB single-table design with GSIs for type lookups.
- **Auth:** Cognito (OIDC).
- **Infra:** Terraform.
- **No photos**, no S3 photo upload flow required.

## Deliverables
- Full working app (frontend + backend + infra).
- Seed script that parses `changes_tomorrow.txt`.
- README with setup + deploy steps.
- Same visual identity as the SLT Sports Cards app, but focused on change relationships.

## Success Criteria
- The graph is the centerpiece: dense, navigable, and informative.
- Cards flip with crisp, scannable details.
- Relationship discovery is effortless (filters + graph + cross-links).
- Data provenance is strictly the file input — no invented content.

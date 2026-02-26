# Change Relationship Cards

A full-stack app for exploring change requests as collectible cards and a GraphDB-style relationship explorer. The UI reuses the EMEA SLT Sports Cards visual system (type, color, spacing, card layout) while shifting the domain to change intelligence.

## Features
- Cards view with flip interaction, search, and filters (division, risk, time window, AI score).
- Force-graph explorer with type filters, legend, and side panel details.
- Admin console for entity CRUD, connection CRUD, and schema template editing.
- Detail drawer with private and shared notes per entity.
- Seed script that parses `data/changes_tomorrow.txt` into DynamoDB (single-table + GSIs).

## Data provenance
All data is derived from `data/changes_tomorrow.txt` (pipe-delimited fixed-width table). No additional records are invented.

## Repo layout
- `frontend/` React + TypeScript + Vite
- `backend/` AWS Lambda (Node 20) + API Gateway
- `infra/` Terraform for DynamoDB, Lambda, API Gateway, Cognito, and frontend hosting
- `data/` source data file

## Local development
### Prerequisites
- Node.js 20
- AWS credentials for DynamoDB access

### Backend
```bash
cd backend
npm install
npm run build
```

Seed DynamoDB (set `TABLE_NAME` and optional `AWS_REGION`):
```bash
RESET_TABLE=true TABLE_NAME=your-table-name npm run seed
```

Optional override for data path:
```bash
CHANGE_DATA_PATH=../data/changes_tomorrow.txt TABLE_NAME=your-table-name npm run seed
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Environment variables (set in `frontend/.env` or shell):
- `VITE_API_BASE` (ex: `http://localhost:3000` or API Gateway URL)
- `VITE_COGNITO_DOMAIN`
- `VITE_COGNITO_CLIENT_ID`
- `VITE_COGNITO_REDIRECT_URI`

If Cognito env vars are unset, the app runs without auth gating.

## Deploy (Terraform)
```bash
cd infra
terraform init
terraform apply
```

After apply:
1. Build the backend bundle: `cd ../backend && npm run build`
2. Re-run `terraform apply` to package the Lambda zip.
3. Build the frontend: `cd ../frontend && npm run build`
4. Sync `frontend/dist` to the frontend S3 bucket from Terraform outputs.

## Notes
- No photos or S3 upload flow required.
- The graph is the primary exploration surface; cards act as a secondary deep-dive view.

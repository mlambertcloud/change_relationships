import { jwtVerify, createRemoteJWKSet } from "jose";

const REGION = process.env.AWS_REGION || "us-east-1";
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || "";
const CLIENT_ID = process.env.COGNITO_CLIENT_ID || "";

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getIssuer() {
  if (!USER_POOL_ID) return "";
  return `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
}

function getJwks() {
  if (!jwks) {
    const issuer = getIssuer();
    jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
  }
  return jwks;
}

export async function verifyAuthHeader(authHeader?: string) {
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new Error("Missing bearer token");
  }
  const token = authHeader.slice("Bearer ".length).trim();
  const issuer = getIssuer();
  if (!issuer || !CLIENT_ID) {
    throw new Error("Auth not configured");
  }
  const { payload } = await jwtVerify(token, getJwks(), { issuer });
  if (payload.token_use !== "access") {
    throw new Error("Invalid token use");
  }
  const clientId = payload.client_id || payload.aud;
  if (clientId !== CLIENT_ID) {
    throw new Error("Invalid client");
  }
  return payload;
}

export function getGroups(payload: Record<string, unknown>) {
  const raw = payload["cognito:groups"];
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === "string") return [raw];
  const role = payload["role"];
  if (typeof role === "string") return [role];
  return [];
}

export function requireGroup(
  payload: Record<string, unknown>,
  allowed: string[]
) {
  if (allowed.length === 0) return true;
  const groups = getGroups(payload);
  return allowed.some((role) => groups.includes(role));
}

function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;

  try {
    const crypto = require("crypto");
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }
}

function parseTokenStructure(token: string): {
  header: string;
  payload: string;
  signature: string;
} | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  return { header: parts[0], payload: parts[1], signature: parts[2] };
}

function safeBase64UrlDecode(str: string): string | null {
  try {
    if (typeof str !== "string") return null;
    let padded = str;
    const padding = 4 - (str.length % 4);
    if (padding && padding !== 4) padded = str + "=".repeat(padding);
    return Buffer.from(padded, "base64").toString("utf-8");
  } catch {
    return null;
  }
}

export function isValidTokenStructure(token: string): boolean {
  const parsed = parseTokenStructure(token);
  if (!parsed) return false;

  const payload = safeBase64UrlDecode(parsed.payload);
  if (!payload) return false;

  try {
    JSON.parse(payload);
    return true;
  } catch {
    return false;
  }
}

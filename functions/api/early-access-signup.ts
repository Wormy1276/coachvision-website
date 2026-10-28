/** Copy to the separate Cloudflare Pages website, NOT CoachVision's routes. */
type Environment = { EARLY_ACCESS_PROXY_SECRET?: string; EARLY_ACCESS_ENDPOINT?: string; EARLY_ACCESS_ENABLED?: string };
type PagesContext = { request: Request; env: Environment };
const ORIGIN = "https://coachvision-website.pages.dev";
const ENDPOINT = "https://app.coachvision.tech/api/public/early-access-signup";

export async function forwardSignup(context: PagesContext, fetcher: typeof fetch = fetch): Promise<Response> {
  const { request, env } = context;
  const headers = { "Cache-Control": "no-store" };
  const reply = (status: number, error: string) => Response.json({ error }, { status, headers });
  // Kept inert until the website owner configures this exact destination after approval.
  if (env.EARLY_ACCESS_ENABLED !== "true" || !env.EARLY_ACCESS_PROXY_SECRET || env.EARLY_ACCESS_ENDPOINT !== ENDPOINT) return reply(503, "Registration is not available yet.");
  if (request.method !== "POST") return reply(405, "Use POST.");
  if (new URL(request.url).origin !== ORIGIN || request.headers.get("origin") !== ORIGIN) return reply(403, "Request not allowed.");
  if (request.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !== "application/json") return reply(415, "Send JSON.");
  // Cloudflare's incoming visitor header; never forward browser-supplied custom IP/secret headers.
  const ip = request.headers.get("cf-connecting-ip");
  if (!ip || ip.length > 45) return reply(503, "Registration is temporarily unavailable.");
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split(".").every((part) => Number(part) <= 255 && String(Number(part)) === part);
  let ipv6 = false;
  if (/^[\da-f:]+$/i.test(ip) && ip.includes(":")) {
    try { ipv6 = new URL(`http://[${ip}]/`).hostname.startsWith("["); } catch { ipv6 = false; }
  }
  if (!ipv4 && !ipv6) return reply(503, "Registration is temporarily unavailable.");
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 8192)) return reply(413, "Submission is too large.");
  const reader = request.body?.getReader();
  if (!reader) return reply(400, "Invalid submission.");
  try {
    const chunks: Uint8Array[] = []; let size = 0;
    while (true) {
      const next = await reader.read(); if (next.done) break;
      size += next.value.byteLength;
      if (size > 8192) { await reader.cancel(); return reply(413, "Submission is too large."); }
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const response = await fetcher(ENDPOINT, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(20000), body: bytes,
      headers: {
        "Content-Type": "application/json", Origin: ORIGIN,
        "x-signup-proxy-secret": env.EARLY_ACCESS_PROXY_SECRET,
        "x-signup-client-ip": ip,
      },
    });
    if (!response.headers.get("content-type")?.includes("application/json")) return reply(503, "Registration is temporarily unavailable.");
    const responseBody = await response.text();
    if (responseBody.length > 4096) return reply(503, "Registration is temporarily unavailable.");
    const result = JSON.parse(responseBody) as { ok?: unknown; error?: unknown; message?: unknown };
    // Do not forward unexpected upstream records or response headers to the visitor.
    if (response.status === 200 && result.ok === true) return Response.json({ ok: true, message: "Thank you. Your registration has been received." }, { headers });
    const status = [400, 403, 413, 415, 429, 503].includes(response.status) ? response.status : 503;
    return Response.json({ error: status === 429 ? "Too many attempts. Please try later." : status === 400 ? "Check your details and complete the security check again." : "Registration is temporarily unavailable." }, {
      status, headers: { ...headers, ...(status === 429 ? { "Retry-After": "600" } : {}) },
    });
  } catch { return reply(503, "Registration is temporarily unavailable."); }
  finally { reader.releaseLock(); }
}

export const onRequest = (context: PagesContext) => forwardSignup(context);

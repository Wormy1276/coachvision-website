
/** Cloudflare Pages registration proxy for CoachVision. */
type Environment = {
  EARLY_ACCESS_PROXY_SECRET?: string;
  EARLY_ACCESS_ENDPOINT?: string;
  EARLY_ACCESS_ENABLED?: string;
};

type PagesContext = {
  request: Request;
  env: Environment;
};

const ORIGIN = "https://coachvision-website.pages.dev";
const ENDPOINT =
  "https://app.coachvision.tech/api/public/early-access-signup";

export async function forwardSignup(
  context: PagesContext,
  fetcher: typeof fetch = fetch
): Promise<Response> {
  const { request, env } = context;
  const headers = { "Cache-Control": "no-store" };
  const started = Date.now();

  const log = (
    stage: string,
    details: Record<string, string | number | boolean> = {}
  ) => {
    console.log(
      JSON.stringify({
        event: "early_access_forward",
        stage,
        ms: Date.now() - started,
        ...details,
      })
    );
  };

  const reply = (status: number, error: string) =>
    Response.json({ error }, { status, headers });

  // Keep registration disabled unless all production settings are valid.
  if (
    env.EARLY_ACCESS_ENABLED !== "true" ||
    !env.EARLY_ACCESS_PROXY_SECRET ||
    env.EARLY_ACCESS_ENDPOINT !== ENDPOINT
  ) {
    log("configuration_failed", {
      enabledValid: env.EARLY_ACCESS_ENABLED === "true",
      secretPresent: Boolean(env.EARLY_ACCESS_PROXY_SECRET),
      endpointValid: env.EARLY_ACCESS_ENDPOINT === ENDPOINT,
    });
    return reply(503, "Registration is not available yet.");
  }

  if (request.method !== "POST") {
    return reply(405, "Use POST.");
  }

  if (
    new URL(request.url).origin !== ORIGIN ||
    request.headers.get("origin") !== ORIGIN
  ) {
    log("origin_rejected");
    return reply(403, "Request not allowed.");
  }

  if (
    request.headers
      .get("content-type")
      ?.split(";")[0]
      .trim()
      .toLowerCase() !== "application/json"
  ) {
    log("content_type_rejected");
    return reply(415, "Send JSON.");
  }

  const ip = request.headers.get("cf-connecting-ip");

  if (!ip || ip.length > 45) {
    log("client_ip_missing");
    return reply(503, "Registration is temporarily unavailable.");
  }

  const ipv4 =
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip
      .split(".")
      .every(
        (part) =>
          Number(part) <= 255 &&
          String(Number(part)) === part
      );

  let ipv6 = false;

  if (/^[\da-f:]+$/i.test(ip) && ip.includes(":")) {
    try {
      ipv6 = new URL(`http://[${ip}]/`).hostname.startsWith("[");
    } catch {
      ipv6 = false;
    }
  }

  if (!ipv4 && !ipv6) {
    log("client_ip_invalid");
    return reply(503, "Registration is temporarily unavailable.");
  }

  const length = request.headers.get("content-length");

  if (
    length &&
    (!/^\d+$/.test(length) || Number(length) > 8192)
  ) {
    log("size_rejected");
    return reply(413, "Submission is too large.");
  }

  const reader = request.body?.getReader();

  if (!reader) {
    log("body_missing");
    return reply(400, "Invalid submission.");
  }

  try {
    const chunks: Uint8Array[] = [];
    let size = 0;

    while (true) {
      const next = await reader.read();
      if (next.done) break;

      size += next.value.byteLength;

      if (size > 8192) {
        await reader.cancel();
        log("size_rejected");
        return reply(413, "Submission is too large.");
      }

      chunks.push(next.value);
    }

    const bytes = new Uint8Array(size);
    let offset = 0;

    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }

    log("forwarding_started");

    const response = await fetcher(ENDPOINT, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(20000),
      body: bytes,
      headers: {
        "Content-Type": "application/json",
        Origin: ORIGIN,
        "x-signup-proxy-secret": env.EARLY_ACCESS_PROXY_SECRET,
        "x-signup-client-ip": ip,
      },
    });

    const contentType =
      response.headers.get("content-type")?.split(";")[0] ?? "none";

    log("upstream_response", {
      status: response.status,
      contentType,
      redirected: response.redirected,
    });

    if (!response.headers.get("content-type")?.includes("application/json")) {
      log("upstream_non_json");
      return reply(503, "Registration is temporarily unavailable.");
    }

    const responseBody = await response.text();

    if (responseBody.length > 4096) {
      log("upstream_body_too_large");
      return reply(503, "Registration is temporarily unavailable.");
    }

    let result: {
      ok?: unknown;
      error?: unknown;
      message?: unknown;
    };

    try {
      result = JSON.parse(responseBody);
    } catch {
      log("upstream_json_invalid");
      return reply(503, "Registration is temporarily unavailable.");
    }

    if (response.status === 200 && result.ok === true) {
      log("registration_success");
      return Response.json(
        {
          ok: true,
          message: "Thank you. Your registration has been received.",
        },
        { headers }
      );
    }

    const status = [400, 403, 413, 415, 429, 503].includes(
      response.status
    )
      ? response.status
      : 503;

    log("upstream_rejected", { status });

    return Response.json(
      {
        error:
          status === 429
            ? "Too many attempts. Please try later."
            : status === 400
              ? "Check your details and complete the security check again."
              : "Registration is temporarily unavailable.",
      },
      {
        status,
        headers: {
          ...headers,
          ...(status === 429 ? { "Retry-After": "600" } : {}),
        },
      }
    );
  } catch (err) {
    const name = err instanceof Error ? err.name : "unknown";

    log(
      name === "TimeoutError"
        ? "timeout"
        : "network_or_redirect",
      { errorType: name }
    );

    return reply(503, "Registration is temporarily unavailable.");
  } finally {
    reader.releaseLock();
  }
}

export const onRequest = (context: PagesContext) =>
  forwardSignup(context);

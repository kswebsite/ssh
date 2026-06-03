export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;   // Serves files from the public/ folder
}

// ==================== PASSWORD HASHING (PBKDF2 + salt – secure for Workers) ====================
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = btoa(String.fromCharCode(...salt));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    256
  );

  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  return `${saltB64}:${hashB64}`;
}

async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (!storedHash.includes(":")) return false;
  const [saltB64, hashB64] = storedHash.split(":");
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    key,
    256
  );

  const computedHash = btoa(String.fromCharCode(...new Uint8Array(derivedBits)));
  return computedHash === hashB64;
}

// ==================== SESSION HELPERS ====================
async function getSessionUser(request: Request, env: Env) {
  // Full Auth & Credits Removal: Skip validation and return default user
  const result = await env.DB.prepare(
    "SELECT id, username, email, created_at FROM users WHERE username = 'ksssh' OR id = 1 LIMIT 1"
  ).first();

  if (!result) {
    return {
      id: 1,
      username: "admin",
      email: "admin@example.com",
      created_at: new Date().toISOString(),
    };
  }

  return {
    id: result.id as number,
    username: result.username as string,
    email: result.email as string,
    created_at: result.created_at as string,
  };
}

// ==================== JSON RESPONSE HELPER ====================
function jsonResponse(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

// ==================== PROXY HELPER ====================
async function proxyTerminal(request: Request, token: string, path: string) {
  let targetUrl = token.startsWith('http') ? token : `https://${token}.trycloudflare.com`;
  if (token.startsWith('ks-lt-')) {
    targetUrl = `https://${token.replace('ks-lt-', '')}.loca.lt`;
  }

  // Ensure path starts with /
  if (!path.startsWith('/')) path = '/' + path;
  const fullUrl = new URL(path, targetUrl).toString();

  // Handle WebSocket Upgrade
  const upgradeHeader = request.headers.get("Upgrade");
  if (upgradeHeader === "websocket") {
    return fetch(fullUrl, request);
  }

  const newHeaders = new Headers();
  // Filter headers to avoid looking like a standard browser request
  const skipHeaders = ['sec-fetch-', 'user-agent', 'cookie', 'dnt', 'referer', 'origin'];
  for (const [key, value] of request.headers.entries()) {
    if (!skipHeaders.some(s => key.toLowerCase().startsWith(s))) {
      newHeaders.set(key, value);
    }
  }

  newHeaders.set("bypass-tunnel-reminder", "1");
  newHeaders.set("Bypass-Tunnel-Reminder", "1");
  newHeaders.set("User-Agent", "localtunnel");
  newHeaders.set("Accept", "*/*");

  const response = await fetch(fullUrl, {
    method: request.method,
    headers: newHeaders,
    body: request.body,
    redirect: "manual"
  });

  // Handle Redirects
  if ([301, 302, 303, 307, 308].includes(response.status)) {
    const location = response.headers.get("Location");
    if (location) {
      const locationUrl = new URL(location, targetUrl);
      if (locationUrl.origin === new URL(targetUrl).origin) {
        // Redirect within the same terminal
        const newLocation = `/terminal/${token}${locationUrl.pathname}${locationUrl.search}${locationUrl.hash}`;
        const resHeaders = new Headers(response.headers);
        resHeaders.set("Location", newLocation);
        return new Response(response.body, { status: response.status, headers: resHeaders });
      }
    }
    return response;
  }

  const contentType = response.headers.get("Content-Type") || "";
  if (contentType.includes("text/html")) {
    // Rewrite absolute paths in HTML to go through the proxy
    return new HTMLRewriter()
      .on("a", {
        element(el) {
          const href = el.getAttribute("href");
          if (href && href.startsWith("/") && !href.startsWith("//")) {
            el.setAttribute("href", `/terminal/${token}${href}`);
          }
        },
      })
      .on("link", {
        element(el) {
          const href = el.getAttribute("href");
          if (href && href.startsWith("/") && !href.startsWith("//")) {
            el.setAttribute("href", `/terminal/${token}${href}`);
          }
        },
      })
      .on("script", {
        element(el) {
          const src = el.getAttribute("src");
          if (src && src.startsWith("/") && !src.startsWith("//")) {
            el.setAttribute("src", `/terminal/${token}${src}`);
          }
        },
      })
      .on("img", {
        element(el) {
          const src = el.getAttribute("src");
          if (src && src.startsWith("/") && !src.startsWith("//")) {
            el.setAttribute("src", `/terminal/${token}${src}`);
          }
        },
      })
      .on("form", {
        element(el) {
          const action = el.getAttribute("action");
          if (action && action.startsWith("/") && !action.startsWith("//")) {
            el.setAttribute("action", `/terminal/${token}${action}`);
          }
        },
      })
      .transform(response);
  }

  return response;
}

// ==================== MAIN WORKER ====================
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
    const url = new URL(request.url);

    // ==================== SERVE STATIC FILES FROM public/ FOLDER ====================
    if (url.pathname === "/") {
      return env.ASSETS.fetch(new URL("/index.html", request.url));
    }

    if (url.pathname === "/auth.html" || url.pathname === "/auth") {
      return Response.redirect(`${url.origin}/`, 302);
    }

    if (url.pathname === "/dashboard.html" || url.pathname === "/dashboard") {
      return env.ASSETS.fetch(new URL("/dashboard.html", request.url));
    }

    if (url.pathname === "/account.html" || url.pathname === "/account") {
      return Response.redirect(`${url.origin}/`, 302);
    }

    // ==================== TERMINAL PROXY ====================
    if (url.pathname.startsWith("/terminal/")) {
      const parts = url.pathname.split("/");
      const token = parts[2];
      const proxyPath = "/" + parts.slice(3).join("/");
      return proxyTerminal(request, token, proxyPath + url.search + url.hash);
    }

    // ==================== API ENDPOINTS ====================

    // ME (Kept for compatibility, returns hardcoded)
    if (url.pathname === "/api/me" && request.method === "GET") {
      return jsonResponse({
        success: true,
        user: {
          id: 1,
          username: "user",
          email: "user@local.storage",
          created_at: new Date().toISOString(),
        },
      });
    }

    // GENERIC STATUS CHECK
    if (url.pathname === "/api/status" && request.method === "GET") {
      const token = url.searchParams.get("token");
      if (!token) return jsonResponse({ error: "Token is required" }, 400);

      let targetUrl = token.startsWith('http') ? token : `https://${token}.trycloudflare.com`;
      if (token.startsWith('ks-lt-')) {
        targetUrl = `https://${token.replace('ks-lt-', '')}.loca.lt`;
      }

      let isOnline = false;
      const maxRetries = 2;

      for (let i = 0; i < maxRetries; i++) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);

          const res = await fetch(targetUrl, {
            method: 'GET',
            signal: controller.signal,
            headers: {
              'User-Agent': 'localtunnel',
              'bypass-tunnel-reminder': '1',
              'Bypass-Tunnel-Reminder': '1',
              'Accept': '*/*'
            }
          });

          clearTimeout(timeoutId);
          // Online if < 502 (excluding 408 Request Timeout)
          isOnline = (res.status < 502 && res.status !== 408);
          if (isOnline) break;
        } catch (e) {
          if (i === maxRetries - 1) break;
          // Short delay before retry
          await new Promise(r => setTimeout(r, 500));
        }
      }

      return new Response(JSON.stringify({ success: true, online: isOnline }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store, no-cache, must-revalidate"
        }
      });
    }


    // WORKSPACES - GET (Returns dummy for local storage mode compatibility)
    if (url.pathname === "/api/workspaces" && request.method === "GET") {
      return jsonResponse({ success: true, workspaces: [{ id: 'default', name: 'Default Workspace', owner_id: 1 }] });
    }


    // Fallback: serve from assets
    const response = await env.ASSETS.fetch(request);
    if (response.status !== 404) {
      return response;
    }

    if (url.pathname.startsWith("/api/")) {
      return jsonResponse({ error: "Not found" }, 404);
    }

    // Asset Resolution Catch-all: If file not found in assets, and we have a terminal token, try proxying
    // This catches absolute paths like /static/js/main.js that don't include the /terminal/token/ prefix
    const cookies = request.headers.get("Cookie") || "";
    const termTokenMatch = cookies.match(/terminal_token=([^;]+)/);
    if (termTokenMatch) {
      const token = termTokenMatch[1];
      return proxyTerminal(request, token, url.pathname + url.search + url.hash);
    }

    return new Response("Not found", { status: 404 });
    } catch (err: any) {
      console.error("API Error:", err);
      return jsonResponse({
        error: "Internal Server Error",
        message: err.message || "An unexpected error occurred"
      }, 500);
    }
  },
};

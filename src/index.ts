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

// ==================== AFK EARNING LOGIC (10 credits per hour, max 24h per claim) ====================
async function claimAFKEarnings(db: D1Database, userId: number) {
  const userStmt = db.prepare("SELECT credits, last_active FROM users WHERE id = ?").bind(userId);
  const user = (await userStmt.first()) as { credits: number; last_active: string } | null;
  if (!user) return { earned: 0, newCredits: 0 };

  const last = new Date(user.last_active);
  const now = new Date();
  const diffMs = Math.max(0, now.getTime() - last.getTime());
  const diffHours = diffMs / (1000 * 60 * 60);

  let earned = Math.floor(diffHours * 10); // 10 credits/hour
  earned = Math.min(earned, 240); // cap at 24 hours

  const newCredits = user.credits + earned;

  await db
    .prepare("UPDATE users SET credits = ?, last_active = CURRENT_TIMESTAMP WHERE id = ?")
    .bind(newCredits, userId)
    .run();

  return { earned, newCredits };
}

// ==================== SESSION HELPERS ====================
async function getSessionUser(request: Request, env: Env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const sessionMatch = cookieHeader.match(/session=([^;]+)/);
  const sessionId = sessionMatch ? sessionMatch[1] : null;
  if (!sessionId) return null;

  const result = await env.DB.prepare(
    `SELECT u.id, u.username, u.email, u.credits 
     FROM sessions s 
     JOIN users u ON s.user_id = u.id 
     WHERE s.id = ? AND s.expires_at > CURRENT_TIMESTAMP`
  )
    .bind(sessionId)
    .first();

  return result
    ? {
        id: result.id as number,
        username: result.username as string,
        email: result.email as string,
        credits: result.credits as number,
      }
    : null;
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

// ==================== MAIN WORKER ====================
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // ==================== SERVE STATIC FILES FROM public/ FOLDER ====================
    if (url.pathname === "/" || url.pathname === "/auth.html") {
      return env.ASSETS.fetch(new URL("/auth.html", request.url));
    }

    if (url.pathname === "/") {
      return env.ASSETS.fetch(new URL("/", request.url));
    }

    if (url.pathname === "/auth.js") {
      return env.ASSETS.fetch(new URL("/auth.js", request.url));
    }

    // ==================== API ENDPOINTS ====================

    // REGISTER
    if (url.pathname === "/api/register" && request.method === "POST") {
      const { username, email, password, confirmPassword } = await request.json();

      if (!username || !email || !password || password !== confirmPassword) {
        return jsonResponse({ error: "All fields required and passwords must match" }, 400);
      }

      try {
        const passwordHash = await hashPassword(password);
        await env.DB.prepare(
          "INSERT INTO users (username, email, password_hash, credits, last_active) VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP)"
        )
          .bind(username.toLowerCase(), email.toLowerCase(), passwordHash)
          .run();

        return jsonResponse({ success: true, message: "Account created successfully" });
      } catch (err: any) {
        if (err.message?.includes("UNIQUE constraint failed")) {
          return jsonResponse({ error: "Username or email already taken" }, 400);
        }
        return jsonResponse({ error: "Registration failed" }, 500);
      }
    }

    // LOGIN
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { identifier, password } = await request.json();
      if (!identifier || !password) {
        return jsonResponse({ error: "Identifier and password required" }, 400);
      }

      const userRow = await env.DB.prepare(
        "SELECT * FROM users WHERE username = ? OR email = ?"
      )
        .bind(identifier.toLowerCase(), identifier.toLowerCase())
        .first();

      if (!userRow || !(await verifyPassword(password, userRow.password_hash as string))) {
        return jsonResponse({ error: "Invalid credentials" }, 401);
      }

      const sessionId = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

      await env.DB.prepare(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
      )
        .bind(sessionId, userRow.id, expiresAt)
        .run();

      const response = jsonResponse({
        success: true,
        username: userRow.username,
        credits: userRow.credits,
      });

      const isHttps = url.protocol === "https:";
      response.headers.append(
        "Set-Cookie",
        `session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800${isHttps ? "; Secure" : ""}`
      );

      return response;
    }

    // ME (with AFK earnings claim)
    if (url.pathname === "/api/me" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const { earned, newCredits } = await claimAFKEarnings(env.DB, user.id);

      return jsonResponse({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          credits: newCredits,
          earned,
        },
      });
    }

    // LOGOUT
    if (url.pathname === "/api/logout" && request.method === "POST") {
      const cookieHeader = request.headers.get("Cookie") || "";
      const sessionMatch = cookieHeader.match(/session=([^;]+)/);
      const sessionId = sessionMatch ? sessionMatch[1] : null;

      if (sessionId) {
        await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
      }

      const response = jsonResponse({ success: true });
      response.headers.append(
        "Set-Cookie",
        "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict"
      );
      return response;
    }

    // Fallback
    return new Response("Not found", { status: 404 });
  },
};

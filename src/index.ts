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
    `SELECT u.id, u.username, u.email, u.credits, u.created_at, u.is_admin
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
        created_at: result.created_at as string,
        is_admin: Boolean(result.is_admin),
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
    if (url.pathname === "/") {
      const user = await getSessionUser(request, env);
      if (!user) {
        return Response.redirect(`${url.origin}/auth.html`, 302);
      }
      return env.ASSETS.fetch(new URL("/index.html", request.url));
    }

    if (url.pathname === "/auth.html" || url.pathname === "/auth") {
      const user = await getSessionUser(request, env);
      if (user) {
        return Response.redirect(`${url.origin}/`, 302);
      }
      return env.ASSETS.fetch(new URL("/auth.html", request.url));
    }

    if (url.pathname === "/dashboard.html" || url.pathname === "/dashboard") {
      return env.ASSETS.fetch(new URL("/dashboard.html", request.url));
    }

    if (url.pathname === "/account.html" || url.pathname === "/account") {
      return env.ASSETS.fetch(new URL("/account.html", request.url));
    }

    if (url.pathname === "/admin.html" || url.pathname === "/admin") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return Response.redirect(`${url.origin}/`, 302);
      return env.ASSETS.fetch(new URL("/admin.html", request.url));
    }

    // ==================== API ENDPOINTS ====================

    // REGISTER
    if (url.pathname === "/api/register" && request.method === "POST") {
      const { username, email, password, confirmPassword } = (await request.json()) as any;

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
      const { identifier, password } = (await request.json()) as any;
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
          created_at: user.created_at,
          is_admin: user.is_admin,
        },
      });
    }

    // UPDATE ACCOUNT
    if (url.pathname === "/api/account/update" && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const { username, newPassword, currentPassword } = (await request.json()) as any;

      // Verify current password
      const userRow = await env.DB.prepare("SELECT password_hash FROM users WHERE id = ?")
        .bind(user.id).first();
      if (!userRow || !(await verifyPassword(currentPassword, userRow.password_hash as string))) {
        return jsonResponse({ error: "Incorrect current password" }, 401);
      }

      if (username) {
        try {
          await env.DB.prepare("UPDATE users SET username = ? WHERE id = ?")
            .bind(username.toLowerCase(), user.id).run();
        } catch (err: any) {
          if (err.message?.includes("UNIQUE")) return jsonResponse({ error: "Username already taken" }, 400);
          throw err;
        }
      }

      if (newPassword) {
        const hash = await hashPassword(newPassword);
        await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?")
          .bind(hash, user.id).run();
      }

      return jsonResponse({ success: true });
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

    // WORKSPACES - GET
    if (url.pathname === "/api/workspaces" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const workspaces = await env.DB.prepare(
        `SELECT w.* FROM workspaces w
         LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
         WHERE w.owner_id = ? OR wm.user_id = ?
         GROUP BY w.id`
      )
        .bind(user.id, user.id)
        .all();

      return jsonResponse({ success: true, workspaces: workspaces.results });
    }

    // WORKSPACES - POST
    if (url.pathname === "/api/workspaces" && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const { name } = (await request.json()) as any;
      if (!name) return jsonResponse({ error: "Name is required" }, 400);

      const id = crypto.randomUUID();

      // Use a transaction or multiple statements
      await env.DB.batch([
        env.DB.prepare("INSERT INTO workspaces (id, name, owner_id) VALUES (?, ?, ?)").bind(id, name, user.id),
        env.DB.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)").bind(id, user.id, 'owner')
      ]);

      return jsonResponse({ success: true, workspace: { id, name } });
    }

    // WORKSPACES - PATCH (Rename)
    if (url.pathname.startsWith("/api/workspaces/") && request.method === "PATCH") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/").pop();
      const { name } = (await request.json()) as any;
      if (!name) return jsonResponse({ error: "Name is required" }, 400);

      const result = await env.DB.prepare("UPDATE workspaces SET name = ? WHERE id = ? AND owner_id = ?")
        .bind(name, id, user.id).run();

      if (result.meta.changes === 0) return jsonResponse({ error: "Unauthorized or not found" }, 403);
      return jsonResponse({ success: true });
    }

    // WORKSPACES - DELETE
    if (url.pathname.startsWith("/api/workspaces/") && request.method === "DELETE") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/").pop();
      const result = await env.DB.prepare("DELETE FROM workspaces WHERE id = ? AND owner_id = ?")
        .bind(id, user.id).run();

      if (result.meta.changes === 0) return jsonResponse({ error: "Unauthorized or not found" }, 403);
      return jsonResponse({ success: true });
    }

    // TERMINALS - GET (With access enforcement)
    if (url.pathname === "/api/terminals" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const workspaceId = url.searchParams.get("workspaceId");

      let query = `
        SELECT t.* FROM terminals t
        JOIN workspaces w ON t.workspace_id = w.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        WHERE (w.owner_id = ? OR wm.user_id = ?)
        AND (
          w.owner_id = ?
          OR wm.terminal_access_type = 'all'
          OR t.id IN (SELECT terminal_id FROM member_terminal_access WHERE user_id = ? AND workspace_id = t.workspace_id)
        )
      `;
      let params: any[] = [user.id, user.id, user.id, user.id, user.id];

      if (workspaceId) {
        query += " AND t.workspace_id = ?";
        params.push(workspaceId);
      }

      const terminals = await env.DB.prepare(query).bind(...params).all();
      return jsonResponse({ success: true, terminals: terminals.results });
    }

    // TERMINALS - POST
    if (url.pathname === "/api/terminals" && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const { name, token, workspaceId } = (await request.json()) as any;
      if (!token || !workspaceId) return jsonResponse({ error: "Token and workspaceId are required" }, 400);

      // Verify access to workspace
      const ws = await env.DB.prepare(
        "SELECT id FROM workspaces WHERE id = ? AND owner_id = ?"
      ).bind(workspaceId, user.id).first();

      // For now only owners can add terminals
      if (!ws) return jsonResponse({ error: "Unauthorized to add to this workspace" }, 403);

      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO terminals (id, name, token, workspace_id) VALUES (?, ?, ?, ?)"
      )
        .bind(id, name || "Terminal", token, workspaceId)
        .run();

      return jsonResponse({ success: true, terminal: { id, name, token, workspaceId } });
    }

    // TERMINALS - DELETE
    if (url.pathname.startsWith("/api/terminals/") && request.method === "DELETE") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/").pop();

      // Verify ownership
      const term = await env.DB.prepare(
        `SELECT t.id FROM terminals t
         JOIN workspaces w ON t.workspace_id = w.id
         WHERE t.id = ? AND w.owner_id = ?`
      ).bind(id, user.id).first();

      if (!term) return jsonResponse({ error: "Not found or unauthorized" }, 404);

      await env.DB.prepare("DELETE FROM terminals WHERE id = ?").bind(id).run();
      return jsonResponse({ success: true });
    }

    // MEMBERS - GET
    if (url.pathname.startsWith("/api/workspaces/") && url.pathname.endsWith("/members") && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const workspaceId = url.pathname.split("/")[3];

      // Verify access
      const ws = await env.DB.prepare(
        "SELECT id FROM workspaces WHERE id = ? AND owner_id = ?"
      ).bind(workspaceId, user.id).first();

      if (!ws) return jsonResponse({ error: "Unauthorized" }, 403);

      const members = await env.DB.prepare(
        `SELECT u.id, u.username, wm.role, wm.terminal_access_type FROM users u
         JOIN workspace_members wm ON u.id = wm.user_id
         WHERE wm.workspace_id = ?`
      ).bind(workspaceId).all();

      const results = await Promise.all(members.results.map(async (m: any) => {
        if (m.terminal_access_type === 'selected') {
          const terminals = await env.DB.prepare("SELECT terminal_id FROM member_terminal_access WHERE workspace_id = ? AND user_id = ?")
            .bind(workspaceId, m.id).all();
          m.terminal_ids = terminals.results.map((t: any) => t.terminal_id);
        }
        return m;
      }));

      return jsonResponse({ success: true, members: results });
    }

    // MEMBERS - POST (Add by username)
    if (url.pathname.startsWith("/api/workspaces/") && url.pathname.endsWith("/members") && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const workspaceId = url.pathname.split("/")[3];
      const { username, role, terminal_access_type, terminal_ids } = (await request.json()) as any;

      // Verify ownership
      const ws = await env.DB.prepare(
        "SELECT id FROM workspaces WHERE id = ? AND owner_id = ?"
      ).bind(workspaceId, user.id).first();

      if (!ws) return jsonResponse({ error: "Unauthorized" }, 403);

      // Find user to add
      const targetUser = (await env.DB.prepare(
        "SELECT id FROM users WHERE username = ?"
      ).bind(username.toLowerCase()).first()) as any;

      if (!targetUser) return jsonResponse({ error: "User not found" }, 404);

      const stmts = [
        env.DB.prepare(
          "INSERT INTO workspace_members (workspace_id, user_id, role, terminal_access_type) VALUES (?, ?, ?, ?)"
        ).bind(workspaceId, targetUser.id, role || 'member', terminal_access_type || 'all')
      ];

      if (terminal_access_type === 'selected' && Array.isArray(terminal_ids)) {
        terminal_ids.forEach(tid => {
          stmts.push(env.DB.prepare("INSERT INTO member_terminal_access (workspace_id, user_id, terminal_id) VALUES (?, ?, ?)")
            .bind(workspaceId, targetUser.id, tid));
        });
      }

      try {
        await env.DB.batch(stmts);
        return jsonResponse({ success: true });
      } catch (e: any) {
        if (e.message?.includes("UNIQUE")) return jsonResponse({ error: "User already a member" }, 400);
        throw e;
      }
    }

    // MEMBERS - PATCH (Update permissions)
    if (url.pathname.startsWith("/api/workspaces/") && url.pathname.includes("/members/") && request.method === "PATCH") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const parts = url.pathname.split("/");
      const workspaceId = parts[3];
      const targetUserId = parts[5];
      const { terminal_access_type, terminal_ids } = (await request.json()) as any;

      // Verify ownership
      const ws = await env.DB.prepare(
        "SELECT id FROM workspaces WHERE id = ? AND owner_id = ?"
      ).bind(workspaceId, user.id).first();

      if (!ws) return jsonResponse({ error: "Unauthorized" }, 403);

      const stmts = [
        env.DB.prepare("UPDATE workspace_members SET terminal_access_type = ? WHERE workspace_id = ? AND user_id = ?")
          .bind(terminal_access_type, workspaceId, targetUserId),
        env.DB.prepare("DELETE FROM member_terminal_access WHERE workspace_id = ? AND user_id = ?")
          .bind(workspaceId, targetUserId)
      ];

      if (terminal_access_type === 'selected' && Array.isArray(terminal_ids)) {
        terminal_ids.forEach(tid => {
          stmts.push(env.DB.prepare("INSERT INTO member_terminal_access (workspace_id, user_id, terminal_id) VALUES (?, ?, ?)")
            .bind(workspaceId, targetUserId, tid));
        });
      }

      await env.DB.batch(stmts);
      return jsonResponse({ success: true });
    }

    // MEMBERS - DELETE
    if (url.pathname.startsWith("/api/workspaces/") && url.pathname.includes("/members/") && request.method === "DELETE") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const parts = url.pathname.split("/");
      const workspaceId = parts[3];
      const targetUserId = parts[5];

      // Verify ownership
      const ws = await env.DB.prepare(
        "SELECT id FROM workspaces WHERE id = ? AND owner_id = ?"
      ).bind(workspaceId, user.id).first();

      if (!ws) return jsonResponse({ error: "Unauthorized" }, 403);

      await env.DB.prepare(
        "DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?"
      ).bind(workspaceId, targetUserId).run();

      return jsonResponse({ success: true });
    }

    // ==================== ADMIN API ====================

    // ADMIN: LIST ALL USERS
    if (url.pathname === "/api/admin/users" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const users = await env.DB.prepare(
        `SELECT id, username, email, credits, last_active, created_at, is_admin FROM users ORDER BY created_at DESC`
      ).all();

      return jsonResponse({ success: true, users: users.results });
    }

    // ADMIN: USER DETAILS (Workspaces + Terminals)
    if (url.pathname.startsWith("/api/admin/users/") && url.pathname.endsWith("/details") && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const targetId = url.pathname.split("/")[4];

      const workspaces = await env.DB.prepare(
        `SELECT w.*, (SELECT COUNT(*) FROM terminals WHERE workspace_id = w.id) as terminal_count
         FROM workspaces w WHERE w.owner_id = ?`
      ).bind(targetId).all();

      const terminals = await env.DB.prepare(
        `SELECT t.*, w.name as workspace_name FROM terminals t
         JOIN workspaces w ON t.workspace_id = w.id
         WHERE w.owner_id = ?`
      ).bind(targetId).all();

      return jsonResponse({ success: true, workspaces: workspaces.results, terminals: terminals.results });
    }

    // ADMIN: UPDATE USER CREDITS
    if (url.pathname.startsWith("/api/admin/users/") && url.pathname.endsWith("/credits") && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const targetId = url.pathname.split("/")[4];
      const { credits } = (await request.json()) as any;

      await env.DB.prepare("UPDATE users SET credits = ? WHERE id = ?")
        .bind(credits, targetId).run();

      return jsonResponse({ success: true });
    }

    // ADMIN: DELETE USER
    if (url.pathname.startsWith("/api/admin/users/") && request.method === "DELETE") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const targetId = url.pathname.split("/")[4];
      if (Number(targetId) === user.id) return jsonResponse({ error: "Cannot delete yourself" }, 400);

      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(targetId).run();
      return jsonResponse({ success: true });
    }

    // Fallback: serve from assets
    const response = await env.ASSETS.fetch(request);
    if (response.status !== 404) {
      return response;
    }

    return new Response("Not found", { status: 404 });
  },
};

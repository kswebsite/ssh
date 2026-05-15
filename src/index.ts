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
  // Full Auth & Credits Removal: Skip validation and return default admin user
  const result = await env.DB.prepare(
    "SELECT id, username, email, created_at, is_admin FROM users WHERE username = 'ksssh' OR is_admin = 1 LIMIT 1"
  ).first();

  if (!result) {
    return {
      id: 1,
      username: "admin",
      email: "admin@example.com",
      created_at: new Date().toISOString(),
      is_admin: true,
    };
  }

  return {
    id: result.id as number,
    username: result.username as string,
    email: result.email as string,
    created_at: result.created_at as string,
    is_admin: result.is_admin === 1,
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

    if (url.pathname === "/admin.html" || url.pathname === "/admin") {
      return env.ASSETS.fetch(new URL("/admin.html", request.url));
    }


    // ==================== API ENDPOINTS ====================

    // ME
    if (url.pathname === "/api/me" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      return jsonResponse({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          created_at: user.created_at,
          is_admin: user.is_admin,
        },
      });
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

    // TERMINALS - RECENT
    if (url.pathname === "/api/terminals/recent" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const recent = await env.DB.prepare(`
        SELECT t.*, MAX(ul.created_at) as last_used
        FROM terminals t
        JOIN usage_logs ul ON t.id = ul.terminal_id
        JOIN workspaces w ON t.workspace_id = w.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        WHERE (w.owner_id = ? OR wm.user_id = ?)
        AND ul.user_id = ?
        GROUP BY t.id
        ORDER BY last_used DESC
        LIMIT 5
      `).bind(user.id, user.id, user.id, user.id).all();

      return jsonResponse({ success: true, terminals: recent.results });
    }

    // TERMINALS - FAVORITE - TOGGLE
    if (url.pathname.startsWith("/api/terminals/") && url.pathname.endsWith("/favorite") && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/")[3];

      const exists = await env.DB.prepare("SELECT 1 FROM favorite_terminals WHERE user_id = ? AND terminal_id = ?")
        .bind(user.id, id).first();

      if (exists) {
        await env.DB.prepare("DELETE FROM favorite_terminals WHERE user_id = ? AND terminal_id = ?")
          .bind(user.id, id).run();
        return jsonResponse({ success: true, favorite: false });
      } else {
        await env.DB.prepare("INSERT INTO favorite_terminals (user_id, terminal_id) VALUES (?, ?)")
          .bind(user.id, id).run();
        return jsonResponse({ success: true, favorite: true });
      }
    }

    // TERMINALS - GET (With access enforcement)
    if (url.pathname === "/api/terminals" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const workspaceId = url.searchParams.get("workspaceId");
      const onlyFavorites = url.searchParams.get("favorites") === "true";

      let query = `
        SELECT t.*, (ft.terminal_id IS NOT NULL) as is_favorite FROM terminals t
        JOIN workspaces w ON t.workspace_id = w.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
        LEFT JOIN favorite_terminals ft ON t.id = ft.terminal_id AND ft.user_id = ?
        WHERE (w.owner_id = ? OR wm.user_id = ?)
        AND (
          w.owner_id = ?
          OR wm.terminal_access_type = 'all'
          OR t.id IN (SELECT terminal_id FROM member_terminal_access WHERE user_id = ? AND workspace_id = t.workspace_id)
        )
      `;
      let params: any[] = [user.id, user.id, user.id, user.id, user.id, user.id];

      if (workspaceId) {
        query += " AND t.workspace_id = ?";
        params.push(workspaceId);
      }
      if (onlyFavorites) {
        query += " AND ft.terminal_id IS NOT NULL";
      }

      const terminals = await env.DB.prepare(query).bind(...params).all();
      return jsonResponse({ success: true, terminals: terminals.results.map((t: any) => ({ ...t, is_favorite: !!t.is_favorite })) });
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

    // TERMINALS - PATCH (Update)
    if (url.pathname.startsWith("/api/terminals/") && request.method === "PATCH") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/").pop();
      const { name, token, workspaceId } = (await request.json()) as any;

      // Verify ownership of original terminal
      const term = await env.DB.prepare(
        `SELECT t.id FROM terminals t
         JOIN workspaces w ON t.workspace_id = w.id
         WHERE t.id = ? AND w.owner_id = ?`
      ).bind(id, user.id).first();

      if (!term) return jsonResponse({ error: "Not found or unauthorized" }, 404);

      // If workspace is being changed, verify ownership of new workspace
      if (workspaceId) {
        const ws = await env.DB.prepare(
          "SELECT id FROM workspaces WHERE id = ? AND owner_id = ?"
        ).bind(workspaceId, user.id).first();
        if (!ws) return jsonResponse({ error: "Unauthorized to move to this workspace" }, 403);
      }

      await env.DB.prepare(
        "UPDATE terminals SET name = COALESCE(?, name), token = COALESCE(?, token), workspace_id = COALESCE(?, workspace_id) WHERE id = ?"
      )
        .bind(name || null, token || null, workspaceId || null, id)
        .run();

      return jsonResponse({ success: true });
    }

    // TERMINALS - USAGE LOGGING (No deduction)
    if (url.pathname === "/api/terminals/usage" && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const { terminalId } = (await request.json()) as any;
      if (!terminalId) return jsonResponse({ error: "Terminal ID is required" }, 400);

      // Verify access to terminal
      const term = (await env.DB.prepare(
        `SELECT t.* FROM terminals t
         JOIN workspaces w ON t.workspace_id = w.id
         LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
         WHERE t.id = ? AND (w.owner_id = ? OR wm.user_id = ?)`
      ).bind(user.id, terminalId, user.id, user.id).first()) as any;

      if (!term) return jsonResponse({ error: "Terminal not found or unauthorized" }, 404);

      await env.DB.prepare("INSERT INTO usage_logs (id, user_id, terminal_id, amount, type) VALUES (?, ?, ?, ?, ?)")
          .bind(crypto.randomUUID(), user.id, terminalId, 0, 'terminal_usage').run();

      return jsonResponse({ success: true });
    }

    // TERMINALS - STATUS CHECK
    if (url.pathname.startsWith("/api/terminals/") && url.pathname.endsWith("/status") && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/")[3];

      const term = (await env.DB.prepare(
        `SELECT t.* FROM terminals t
         JOIN workspaces w ON t.workspace_id = w.id
         LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.user_id = ?
         WHERE t.id = ? AND (w.owner_id = ? OR wm.user_id = ?)`
      ).bind(user.id, id, user.id, user.id).first()) as any;

      if (!term) return jsonResponse({ error: "Not found or unauthorized" }, 404);

      const targetUrl = term.token.startsWith('http') ? term.token : `https://${term.token}.trycloudflare.com`;

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);

        const res = await fetch(targetUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'User-Agent': 'KS-SSH-Status-Check' }
        });

        clearTimeout(timeoutId);
        return jsonResponse({ success: true, online: res.ok || res.status === 401 || res.status === 403 || res.status === 404 });
        // We consider it online if we get ANY response from the server, even error codes, as long as it's not a timeout/network error
      } catch (e) {
        return jsonResponse({ success: true, online: false });
      }
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
        `SELECT id, username, email, credits, last_active, created_at, is_admin, is_banned FROM users ORDER BY created_at DESC`
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

    // ADMIN: BAN/UNBAN USER
    if (url.pathname.startsWith("/api/admin/users/") && url.pathname.endsWith("/ban") && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const targetId = url.pathname.split("/")[4];
      const { banned } = (await request.json()) as any;

      await env.DB.prepare("UPDATE users SET is_banned = ? WHERE id = ?")
        .bind(banned ? 1 : 0, targetId).run();

      return jsonResponse({ success: true });
    }

    // ADMIN: PROMOTE TO ADMIN
    if (url.pathname.startsWith("/api/admin/users/") && url.pathname.endsWith("/promote") && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const targetId = url.pathname.split("/")[4];
      await env.DB.prepare("UPDATE users SET is_admin = 1 WHERE id = ?")
        .bind(targetId).run();

      return jsonResponse({ success: true });
    }

    // ADMIN: COUPONS - LIST
    if (url.pathname === "/api/admin/coupons" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const coupons = await env.DB.prepare("SELECT * FROM coupons ORDER BY created_at DESC").all();
      return jsonResponse({ success: true, coupons: coupons.results });
    }

    // ADMIN: COUPONS - CREATE
    if (url.pathname === "/api/admin/coupons" && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const { code, reward, max_uses, expires_at } = (await request.json()) as any;
      if (!code || !reward) return jsonResponse({ error: "Code and reward are required" }, 400);

      const id = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO coupons (id, code, reward, max_uses, expires_at) VALUES (?, ?, ?, ?, ?)"
      )
        .bind(id, code.toUpperCase(), reward, max_uses || 1, expires_at || null)
        .run();

      return jsonResponse({ success: true });
    }

    // ADMIN: COUPONS - DELETE
    if (url.pathname.startsWith("/api/admin/coupons/") && request.method === "DELETE") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.pathname.split("/").pop();
      await env.DB.prepare("DELETE FROM coupons WHERE id = ?").bind(id).run();
      return jsonResponse({ success: true });
    }

    // ADMIN: CONFIG - GET
    if (url.pathname === "/api/admin/settings" && request.method === "GET") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const config = await env.DB.prepare("SELECT * FROM config").all();
      const settings = config.results.reduce((acc: any, row: any) => {
        acc[row.key] = row.value;
        return acc;
      }, {});

      return jsonResponse({ success: true, settings });
    }

    // ADMIN: CONFIG - UPDATE
    if (url.pathname === "/api/admin/settings" && request.method === "POST") {
      const user = await getSessionUser(request, env);
      if (!user || !user.is_admin) return jsonResponse({ error: "Unauthorized" }, 401);

      const settings = (await request.json()) as any;
      const stmts = Object.entries(settings).map(([key, value]) =>
        env.DB.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").bind(key, String(value))
      );

      if (stmts.length === 0) return jsonResponse({ success: true });

      await env.DB.batch(stmts);
      return jsonResponse({ success: true });
    }

    // Fallback: serve from assets
    const response = await env.ASSETS.fetch(request);
    if (response.status !== 404) {
      return response;
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

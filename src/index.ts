export interface Env {
  DB: D1Database;
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

// ==================== STATIC FILES (served by the Worker) ====================
const AUTH_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSH • Login / Register</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;display=swap');
    body { font-family: 'Inter', system_ui, sans-serif; }
  </style>
</head>
<body class="bg-gray-950 text-white min-h-screen flex items-center justify-center">
  <div class="max-w-md w-full mx-4">
    <div class="bg-gray-900 rounded-3xl shadow-2xl p-8">
      <div class="flex justify-center mb-8">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 bg-emerald-500 rounded-2xl flex items-center justify-center text-xl">🔑</div>
          <h1 class="text-3xl font-semibold tracking-tight">SSH</h1>
        </div>
      </div>

      <div class="flex border-b border-gray-800 mb-6">
        <button onclick="switchTab(0)" id="tab-login" class="flex-1 pb-4 text-lg font-medium border-b-2 border-emerald-500 text-white">Login</button>
        <button onclick="switchTab(1)" id="tab-register" class="flex-1 pb-4 text-lg font-medium text-gray-400">Register</button>
      </div>

      <!-- LOGIN FORM -->
      <div id="login-form">
        <form onsubmit="handleLogin(event)">
          <div class="space-y-5">
            <div>
              <label class="text-sm text-gray-400 block mb-1">Email or Username</label>
              <input id="login-identifier" type="text" required
                     class="w-full bg-gray-800 border border-gray-700 focus:border-emerald-500 rounded-2xl px-4 py-3 outline-none text-white">
            </div>
            <div>
              <label class="text-sm text-gray-400 block mb-1">Password</label>
              <input id="login-password" type="password" required
                     class="w-full bg-gray-800 border border-gray-700 focus:border-emerald-500 rounded-2xl px-4 py-3 outline-none text-white">
            </div>
            <button type="submit"
                    class="w-full bg-emerald-500 hover:bg-emerald-600 transition py-4 rounded-2xl font-semibold text-lg">
              Login
            </button>
          </div>
        </form>
        <p id="login-error" class="text-red-400 text-center mt-4 text-sm hidden"></p>
      </div>

      <!-- REGISTER FORM -->
      <div id="register-form" class="hidden">
        <form onsubmit="handleRegister(event)">
          <div class="space-y-5">
            <div>
              <label class="text-sm text-gray-400 block mb-1">Username</label>
              <input id="reg-username" type="text" required
                     class="w-full bg-gray-800 border border-gray-700 focus:border-emerald-500 rounded-2xl px-4 py-3 outline-none text-white">
            </div>
            <div>
              <label class="text-sm text-gray-400 block mb-1">Email</label>
              <input id="reg-email" type="email" required
                     class="w-full bg-gray-800 border border-gray-700 focus:border-emerald-500 rounded-2xl px-4 py-3 outline-none text-white">
            </div>
            <div>
              <label class="text-sm text-gray-400 block mb-1">Password</label>
              <input id="reg-password" type="password" required
                     class="w-full bg-gray-800 border border-gray-700 focus:border-emerald-500 rounded-2xl px-4 py-3 outline-none text-white">
            </div>
            <div>
              <label class="text-sm text-gray-400 block mb-1">Confirm Password</label>
              <input id="reg-confirm" type="password" required
                     class="w-full bg-gray-800 border border-gray-700 focus:border-emerald-500 rounded-2xl px-4 py-3 outline-none text-white">
            </div>
            <button type="submit"
                    class="w-full bg-emerald-500 hover:bg-emerald-600 transition py-4 rounded-2xl font-semibold text-lg">
              Create Account
            </button>
          </div>
        </form>
        <p id="register-error" class="text-red-400 text-center mt-4 text-sm hidden"></p>
      </div>

      <p class="text-center text-xs text-gray-500 mt-8">
        Your credits increase while you're AFK.<br>Come back later and claim them!
      </p>
    </div>
  </div>

  <script src="/auth.js"></script>
</body>
</html>`;

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSH • Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;display=swap');
    body { font-family: 'Inter', system_ui, sans-serif; }
  </style>
</head>
<body class="bg-gray-950 text-white min-h-screen">
  <div class="max-w-5xl mx-auto p-8">
    <div class="flex justify-between items-center mb-12">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 bg-emerald-500 rounded-2xl flex items-center justify-center text-2xl">🔑</div>
        <h1 class="text-4xl font-semibold tracking-tight">SSH</h1>
      </div>
      <div class="flex items-center gap-6">
        <div onclick="logout()" class="cursor-pointer flex items-center gap-2 text-gray-400 hover:text-white">
          <span class="text-sm font-medium">Logout</span>
          <span class="text-xl">→</span>
        </div>
      </div>
    </div>

    <div class="bg-gray-900 rounded-3xl p-8 mb-8">
      <div class="flex justify-between items-start">
        <div>
          <p class="text-emerald-400 text-sm font-medium">WELCOME BACK</p>
          <h2 id="username-display" class="text-5xl font-semibold mt-1">Loading...</h2>
        </div>
        <div class="text-right">
          <p class="text-gray-400 text-sm">YOUR CREDITS</p>
          <div id="credits-display" class="text-7xl font-bold text-emerald-400 mt-1 tabular-nums">0</div>
        </div>
      </div>

      <div id="afk-message" class="mt-6 bg-emerald-900/30 border border-emerald-500/30 rounded-2xl p-4 hidden">
        <p class="text-emerald-400 font-medium">🎉 AFK Earnings claimed!</p>
        <p id="earned-text" class="text-emerald-300"></p>
      </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div class="bg-gray-900 rounded-3xl p-8">
        <h3 class="text-xl font-semibold mb-4">How AFK Earning Works</h3>
        <ul class="space-y-4 text-gray-300">
          <li class="flex gap-3"><span class="text-emerald-400">•</span> You earn <strong>10 credits per hour</strong> while away from the dashboard</li>
          <li class="flex gap-3"><span class="text-emerald-400">•</span> Credits are automatically calculated and added when you visit</li>
          <li class="flex gap-3"><span class="text-emerald-400">•</span> Maximum 240 credits per visit (24 hours)</li>
          <li class="flex gap-3"><span class="text-emerald-400">•</span> Last active time is updated after every claim</li>
        </ul>
      </div>
      <div class="bg-gray-900 rounded-3xl p-8 flex flex-col justify-center">
        <p class="text-3xl font-medium text-center">System Credits</p>
        <p id="system-note" class="text-center text-gray-400 mt-6 text-lg">Your balance updates live.<br>Stay AFK and watch it grow!</p>
        <div class="flex-1"></div>
        <button onclick="refreshCredits()" 
                class="mt-auto w-full py-4 bg-white text-gray-900 rounded-2xl font-semibold text-lg hover:bg-emerald-400 transition">
          Refresh Credits Now
        </button>
      </div>
    </div>
  </div>

  <script>
    let currentUser = null;

    async function loadDashboard() {
      const res = await fetch('/api/me');
      if (!res.ok) {
        window.location.href = '/auth.html';
        return;
      }
      const data = await res.json();
      currentUser = data.user;

      document.getElementById('username-display').textContent = currentUser.username;
      document.getElementById('credits-display').textContent = currentUser.credits;

      if (currentUser.earned && currentUser.earned > 0) {
        const msg = document.getElementById('afk-message');
        msg.classList.remove('hidden');
        document.getElementById('earned-text').innerHTML = 
          \`You earned <strong>\${currentUser.earned}</strong> credits while AFK!\`;
      }
    }

    async function refreshCredits() {
      const res = await fetch('/api/me');
      if (res.ok) {
        const data = await res.json();
        currentUser = data.user;
        document.getElementById('credits-display').textContent = currentUser.credits;
        
        const msg = document.getElementById('afk-message');
        if (currentUser.earned && currentUser.earned > 0) {
          msg.classList.remove('hidden');
          document.getElementById('earned-text').innerHTML = 
            \`You earned <strong>\${currentUser.earned}</strong> credits while AFK!\`;
        }
      }
    }

    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      window.location.href = '/auth.html';
    }

    // Tailwind script
    document.documentElement.setAttribute('data-theme', 'dark');
    loadDashboard();
  </script>
</body>
</html>`;

const AUTH_JS = `// auth.js – Client-side logic for auth.html
function switchTab(n) {
  document.getElementById('login-form').classList.toggle('hidden', n === 1);
  document.getElementById('register-form').classList.toggle('hidden', n === 0);
  document.getElementById('tab-login').classList.toggle('border-emerald-500', n === 0);
  document.getElementById('tab-login').classList.toggle('text-white', n === 0);
  document.getElementById('tab-login').classList.toggle('text-gray-400', n === 1);
  document.getElementById('tab-register').classList.toggle('border-emerald-500', n === 1);
  document.getElementById('tab-register').classList.toggle('text-white', n === 1);
  document.getElementById('tab-register').classList.toggle('text-gray-400', n === 0);
}

async function handleLogin(e) {
  e.preventDefault();
  const errorEl = document.getElementById('login-error');
  errorEl.classList.add('hidden');

  const identifier = document.getElementById('login-identifier').value.trim();
  const password = document.getElementById('login-password').value;

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, password })
  });

  const data = await res.json();
  if (!res.ok) {
    errorEl.textContent = data.error || 'Login failed';
    errorEl.classList.remove('hidden');
    return;
  }

  // Cookie is set by backend – just redirect
  window.location.href = '/dashboard.html';
}

async function handleRegister(e) {
  e.preventDefault();
  const errorEl = document.getElementById('register-error');
  errorEl.classList.add('hidden');

  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirm = document.getElementById('reg-confirm').value;

  if (password !== confirm) {
    errorEl.textContent = 'Passwords do not match';
    errorEl.classList.remove('hidden');
    return;
  }

  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, confirmPassword: confirm })
  });

  const data = await res.json();
  if (!res.ok) {
    errorEl.textContent = data.error || 'Registration failed';
    errorEl.classList.remove('hidden');
    return;
  }

  alert('Account created! Please login.');
  switchTab(0); // switch to login tab
}

// Tailwind initialization
function initTailwind() {
  // Already initialized via script tag in HTML
}
`;

// ==================== MAIN WORKER ====================
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Serve static HTML + JS
    if (url.pathname === "/" || url.pathname === "/auth.html") {
      return new Response(AUTH_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/dashboard.html") {
      return new Response(DASHBOARD_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/auth.js") {
      return new Response(AUTH_JS, {
        headers: { "Content-Type": "application/javascript; charset=utf-8" },
      });
    }

    // API endpoints
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

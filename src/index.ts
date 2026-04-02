import { authhtml } from "./authhtml";
import { dashboardhtml } from "./dashboardhtml";   // ← create this file next to index.ts (same format as authhtml.ts)

export interface Env {
	DB: D1Database;
}

export default {
	async fetch(request: Request, env: Env) {
		const url = new URL(request.url);

		// ====================== AUTH PAGE ======================
		if (url.pathname === "/auth" || url.pathname === "/login") {
			return new Response(authhtml, {
				headers: {
					"content-type": "text/html;charset=UTF-8",
				},
			});
		}

		// ====================== DASHBOARD PAGE ======================
		if (url.pathname === "/" || url.pathname === "/dashboard") {
			let results: any[] = [];

			try {
				// You can change the query if you need more/less data
				const stmt = env.DB.prepare(`
					SELECT * FROM comments 
					ORDER BY id DESC 
					LIMIT 10
				`);
				const { results: r } = await stmt.all();
				results = r ?? [];
			} catch (err) {
				// Table doesn't exist yet → we show empty list (or you can create it first)
				console.error("DB query failed:", err);
			}

			// Inject the comments data into the dashboard HTML
			// (dashboardhtml must contain </body> – most normal HTML files do)
			let html = dashboardhtml;

			const dataScript = `
				<script>
					window.initialComments = ${JSON.stringify(results, null, 2)};
				</script>
			`;

			// Safe insert right before </body>
			if (html.includes("</body>")) {
				html = html.replace("</body>", dataScript + "</body>");
			} else {
				// Fallback: just append at the end
				html += dataScript;
			}

			return new Response(html, {
				headers: {
					"content-type": "text/html;charset=UTF-8",
				},
			});
		}

		// Optional: simple API endpoint if your dashboard HTML wants to fetch data via JS
		if (url.pathname === "/api/comments") {
			const stmt = env.DB.prepare("SELECT * FROM comments ORDER BY id DESC LIMIT 10");
			const { results } = await stmt.all();

			return new Response(JSON.stringify(results), {
				headers: {
					"content-type": "application/json",
				},
			});
		}

		// 404 for everything else
		return new Response("Not Found", { status: 404 });
	},
} satisfies ExportedHandler<Env>;

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

// Fork hardening: aliases and domain routing rules are admin-only, and first-run
// setup needs the operator's SETUP_TOKEN. Each test drives the real route handler.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const directory = mkdtempSync(join(root, "node_modules", "mailflare-hardening-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
await build({
	stdin: {
		contents: `
			export { SqliteDatabase } from "./server/runtime/sqlite-database.ts";
			export { applyMigrations } from "./server/runtime/migrate.ts";
			export { createSession } from "./src/lib/auth/session.ts";
			export { SETUP_TOKEN_HEADER } from "./src/lib/auth/setup-token-utils.ts";
			export { POST as createAlias, DELETE as deleteAlias } from "./src/app/api/mailboxes/[id]/aliases/route.ts";
			export { POST as createDomainRule } from "./src/app/api/routing-rules/domain/route.ts";
			export { PATCH as updateDomainRule, DELETE as deleteDomainRule } from "./src/app/api/routing-rules/domain/[id]/route.ts";
			export { POST as register } from "./src/app/api/auth/register/route.ts";
			export { POST as setupDomain } from "./src/app/api/setup/domain/route.ts";
			export { POST as setupPrepare } from "./src/app/api/setup/prepare/route.ts";
		`,
		resolveDir: root,
		sourcefile: "security-hardening-test-entry.ts",
	},
	outfile: join(directory, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node24",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	alias: { "next/headers": "next/headers.js", "next/server": "next/server.js", "cloudflare:workers": "./server/runtime/cloudflare-workers.ts" },
	logLevel: "silent",
});
const {
	SqliteDatabase, applyMigrations, createSession, SETUP_TOKEN_HEADER,
	createAlias, deleteAlias, createDomainRule, updateDomainRule, deleteDomainRule,
	register, setupDomain, setupPrepare,
} = await import(pathToFileURL(join(directory, "entry.mjs")).href);

async function fixture(t, { withUsers = true, env: extraEnv = {} } = {}) {
	const database = new SqliteDatabase(":memory:");
	t.after(() => database.db.close());
	await applyMigrations(database, join(root, "drizzle/migrations"));
	if (withUsers) {
		database.db.exec(`
			INSERT INTO users (id, email, password_hash, name, role, is_primary_admin, created_at) VALUES
				('admin', 'owner@one.test', 'hash', 'Owner', 'admin', 1, 1),
				('staff', 'staff@one.test', 'hash', 'Staff', 'user', 0, 1);
			INSERT INTO domains (id, user_id, hostname, zone_id, status, created_at) VALUES
				('one', 'admin', 'one.test', 'zone-one', 'active', 1),
				('two', 'admin', 'two.test', 'zone-two', 'active', 1);
			INSERT INTO mailboxes (id, user_id, domain_id, local_part, use_all_domains, created_at) VALUES
				('owner-mbx', 'admin', 'one', 'owner', 0, 1),
				('staff-mbx', 'staff', 'one', 'staff', 0, 1),
				('boss-mbx', 'admin', 'one', 'boss', 1, 1);
		`);
	}
	const env = { DB: database, CF_TOKEN: "test-only", MAILFLARE_RUNTIME: "node", ...extraEnv };
	globalThis.__mailflareNodeEnv = env;
	t.after(() => { delete globalThis.__mailflareNodeEnv; });
	const calls = [];
	t.mock.method(globalThis, "fetch", async (url, init = {}) => {
		const parsed = new URL(url);
		assert.equal(parsed.origin, "https://api.cloudflare.com", "tests must never contact a real service");
		calls.push({ method: init.method ?? "GET", path: parsed.pathname });
		if ((init.method ?? "GET") === "POST") return Response.json({ success: true, result: { id: `rule-${calls.length}` } });
		return Response.json({ success: true, result: [] });
	});
	const sessions = withUsers
		? { admin: await createSession(env, "admin"), staff: await createSession(env, "staff") }
		: {};
	const request = (path, { as, method = "POST", body, headers = {} } = {}) => new Request(`https://mailflare.test${path}`, {
		method,
		headers: { ...(as ? { Authorization: `Bearer ${sessions[as]}` } : {}), "Content-Type": "application/json", ...headers },
		...(body ? { body: JSON.stringify(body) } : {}),
	});
	const params = (values) => ({ params: Promise.resolve(values) });
	const count = (sql) => database.db.prepare(sql).get().n;
	return { database, calls, request, params, count };
}

const rejectAll = { domainId: "one", matchField: "sender", matchOperator: "contains", matchValue: "@", action: "reject" };

test("a non-admin cannot claim postmaster@ (or any address) as an alias", async (t) => {
	const f = await fixture(t);
	const response = await createAlias(
		f.request("/api/mailboxes/staff-mbx/aliases", { as: "staff", body: { localPart: "postmaster", domainId: "one" } }),
		f.params({ id: "staff-mbx" }),
	);
	assert.equal(response.status, 403);
	assert.equal(f.count("SELECT COUNT(*) AS n FROM mailbox_aliases"), 0);
	assert.equal(f.calls.length, 0, "no Cloudflare routing rule is created");
});

test("a non-admin cannot delete an alias", async (t) => {
	const f = await fixture(t);
	f.database.db.exec("INSERT INTO mailbox_aliases (id, mailbox_id, domain_id, local_part, created_at) VALUES ('als', 'staff-mbx', 'one', 'sales', 1)");
	const response = await deleteAlias(f.request("/api/mailboxes/staff-mbx/aliases?aliasId=als", { as: "staff", method: "DELETE" }), f.params({ id: "staff-mbx" }));
	assert.equal(response.status, 403);
	assert.equal(f.count("SELECT COUNT(*) AS n FROM mailbox_aliases"), 1);
});

test("an admin can still create aliases", async (t) => {
	const f = await fixture(t);
	const response = await createAlias(
		f.request("/api/mailboxes/owner-mbx/aliases", { as: "admin", body: { localPart: "postmaster", domainId: "one" } }),
		f.params({ id: "owner-mbx" }),
	);
	assert.equal(response.status, 200);
	assert.equal(f.count("SELECT COUNT(*) AS n FROM mailbox_aliases WHERE local_part = 'postmaster'"), 1);
});

test("an alias cannot shadow an address a use-all-domains mailbox already receives", async (t) => {
	const f = await fixture(t);
	// boss@two.test already reaches boss-mbx through use_all_domains.
	const response = await createAlias(
		f.request("/api/mailboxes/owner-mbx/aliases", { as: "admin", body: { localPart: "boss", domainId: "two" } }),
		f.params({ id: "owner-mbx" }),
	);
	assert.equal(response.status, 409);
	assert.equal(f.count("SELECT COUNT(*) AS n FROM mailbox_aliases"), 0);
});

test("a non-admin cannot create a domain-wide rule, even through their own mailbox", async (t) => {
	const f = await fixture(t);
	for (const path of ["/api/routing-rules/domain", "/api/routing-rules/domain?mailboxId=staff-mbx"]) {
		const response = await createDomainRule(f.request(path, { as: "staff", body: rejectAll }));
		assert.equal(response.status, 403, path);
	}
	assert.equal(f.count("SELECT COUNT(*) AS n FROM routing_rules WHERE scope = 'domain'"), 0);
});

test("a non-admin cannot edit or delete the admin's domain rules", async (t) => {
	const f = await fixture(t);
	f.database.db.exec(`INSERT INTO routing_rules (id, user_id, domain_id, scope, pattern, match_field, match_operator, match_value, action, mailbox_id, created_at)
		VALUES ('catch-all', 'admin', 'one', 'domain', '@', 'recipient', 'contains', '@', 'store', 'owner-mbx', 1)`);
	const patch = await updateDomainRule(
		f.request("/api/routing-rules/domain/catch-all?mailboxId=staff-mbx", { as: "staff", method: "PATCH", body: { ...rejectAll, action: "store", mailboxId: "staff-mbx" } }),
		f.params({ id: "catch-all" }),
	);
	assert.equal(patch.status, 403);
	const remove = await deleteDomainRule(f.request("/api/routing-rules/domain/catch-all?mailboxId=staff-mbx", { as: "staff", method: "DELETE" }), f.params({ id: "catch-all" }));
	assert.equal(remove.status, 403);
	const rule = f.database.db.prepare("SELECT action, mailbox_id FROM routing_rules WHERE id = 'catch-all'").get();
	assert.deepEqual({ ...rule }, { action: "store", mailbox_id: "owner-mbx" });
});

test("an admin can still manage domain rules from the admin page and the settings page", async (t) => {
	const f = await fixture(t);
	for (const path of ["/api/routing-rules/domain", "/api/routing-rules/domain?mailboxId=owner-mbx"]) {
		const response = await createDomainRule(f.request(path, { as: "admin", body: rejectAll }));
		assert.equal(response.status, 200, path);
	}
	assert.equal(f.count("SELECT COUNT(*) AS n FROM routing_rules WHERE scope = 'domain'"), 2);
});

const firstAdmin = { domain: "company.test", username: "attacker", password: "attacker-password-1", resetEmail: "a@evil.test", replaceMxRecords: true };

test("first-run setup is closed when no SETUP_TOKEN is configured", async (t) => {
	const f = await fixture(t, { withUsers: false });
	assert.equal((await register(f.request("/api/auth/register", { body: firstAdmin }))).status, 403);
	assert.equal((await setupDomain(f.request("/api/setup/domain", { body: { hostname: "company.test" } }))).status, 403);
	assert.equal((await setupPrepare(f.request("/api/setup/prepare"))).status, 403);
	assert.equal(f.count("SELECT COUNT(*) AS n FROM users"), 0);
	assert.equal(f.calls.length, 0, "CF_TOKEN is never used");
});

test("first-run setup rejects a missing or wrong token", async (t) => {
	const f = await fixture(t, { withUsers: false, env: { SETUP_TOKEN: "operator-secret" } });
	for (const headers of [{}, { [SETUP_TOKEN_HEADER]: "guess" }, { [SETUP_TOKEN_HEADER]: "operator-secre" }]) {
		assert.equal((await register(f.request("/api/auth/register", { body: firstAdmin, headers }))).status, 403);
		assert.equal((await setupDomain(f.request("/api/setup/domain", { body: { hostname: "company.test" }, headers }))).status, 403);
	}
	assert.equal(f.count("SELECT COUNT(*) AS n FROM users"), 0);
	assert.equal(f.calls.length, 0, "CF_TOKEN is never used");
});

test("the operator's token opens first-run setup", async (t) => {
	const f = await fixture(t, { withUsers: false, env: { SETUP_TOKEN: "operator-secret" } });
	const response = await setupDomain(f.request("/api/setup/domain", { body: { hostname: "company.test" }, headers: { [SETUP_TOKEN_HEADER]: "operator-secret" } }));
	// Past the gate: the zone lookup runs (and finds nothing in this mock).
	assert.notEqual(response.status, 403);
	assert.ok(f.calls.some((call) => call.path === "/client/v4/zones"));
});

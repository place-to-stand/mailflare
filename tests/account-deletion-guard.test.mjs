import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

// Fork hardening: deleting an account must never take other people's mail with it.
// Purging a user cascades to the domains, mailboxes and messages that point at them.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const directory = mkdtempSync(join(root, "node_modules", "mailflare-account-deletion-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
await build({
	stdin: {
		contents: `
			export { SqliteDatabase } from "./server/runtime/sqlite-database.ts";
			export { applyMigrations } from "./server/runtime/migrate.ts";
			export { deleteAccounts, runAccountRetention } from "./src/lib/accounts/deletion.ts";
		`,
		resolveDir: root,
		sourcefile: "account-deletion-test-entry.ts",
	},
	outfile: join(directory, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node24",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	alias: {
		"next/headers": "next/headers.js",
		"next/server": "next/server.js",
		"cloudflare:workers": "./server/runtime/cloudflare-workers.ts",
	},
	logLevel: "silent",
});
const { SqliteDatabase, applyMigrations, deleteAccounts, runAccountRetention } = await import(pathToFileURL(join(directory, "entry.mjs")).href);

const actor = { id: "owner", role: "admin", isPrimaryAdmin: true, canManageUsers: true, canManageDomains: true, createdByUserId: null };

async function fixture(t) {
	const database = new SqliteDatabase(":memory:");
	t.after(() => database.db.close());
	await applyMigrations(database, join(root, "drizzle/migrations"));
	database.db.exec(`
		INSERT INTO users (id, email, password_hash, name, role, is_primary_admin, created_at) VALUES
			('owner', 'owner@one.test', 'hash', 'Owner', 'admin', 1, 1),
			('helper', 'helper@one.test', 'hash', 'Helper', 'admin', 0, 1),
			('staff', 'staff@one.test', 'hash', 'Staff', 'user', 0, 1);
		INSERT INTO domains (id, user_id, hostname, zone_id, status, created_at) VALUES
			('one', 'owner', 'one.test', 'manual', 'active', 1),
			('two', 'helper', 'two.test', 'manual', 'active', 1);
		INSERT INTO mailboxes (id, user_id, domain_id, local_part, use_all_domains, created_at) VALUES
			('owner-mbx', 'owner', 'one', 'owner', 0, 1),
			('staff-mbx', 'staff', 'one', 'staff', 0, 1),
			('helper-mbx', 'helper', 'two', 'helper', 0, 1);
	`);
	const deletedKeys = [];
	const env = { DB: database, MAILFLARE_RUNTIME: "node", BUCKET: { delete: async (keys) => { deletedKeys.push(keys); } } };
	globalThis.__mailflareNodeEnv = env;
	t.after(() => { delete globalThis.__mailflareNodeEnv; });
	t.mock.method(globalThis, "fetch", async () => { throw new Error("tests must never contact a real service"); });
	const count = (sql) => database.db.prepare(sql).get().n;
	return { database, env, count };
}

test("an account that owns a domain with other people's mailboxes cannot be deleted", async (t) => {
	const { env, database } = await fixture(t);
	database.db.exec(`INSERT INTO mailboxes (id, user_id, domain_id, local_part, use_all_domains, created_at) VALUES ('staff-two', 'staff', 'two', 'staff', 0, 1)`);
	const result = await deleteAccounts(env, actor, { ids: ["helper"], transferToId: null });
	assert.equal(result.ok, false);
	assert.equal(result.status, 409);
	assert.equal(database.db.prepare("SELECT deleted_at FROM users WHERE id = 'helper'").get().deleted_at, null);
});

test("an account that owns a shared mailbox cannot be deleted", async (t) => {
	const { env, database } = await fixture(t);
	database.db.exec(`INSERT INTO mailbox_access (id, mailbox_id, user_id, permission, created_at) VALUES ('share', 'helper-mbx', 'staff', 'read_only', 1)`);
	const result = await deleteAccounts(env, actor, { ids: ["helper"], transferToId: null });
	assert.equal(result.ok, false);
	assert.equal(result.status, 409);
});

test("the purge refuses an account whose mailbox was shared after it was deleted", async (t) => {
	const { env, database, count } = await fixture(t);
	assert.equal((await deleteAccounts(env, actor, { ids: ["helper"], transferToId: null })).ok, true);
	database.db.exec(`
		INSERT INTO mailbox_access (id, mailbox_id, user_id, permission, created_at) VALUES ('share', 'helper-mbx', 'staff', 'read_only', 1);
		UPDATE users SET deleted_at = 1 WHERE id = 'helper';
	`);
	t.mock.method(console, "error", () => {});
	assert.equal(await runAccountRetention(env, new Date()), 0);
	assert.equal(count("SELECT COUNT(*) AS n FROM users WHERE id = 'helper'"), 1);
	assert.equal(count("SELECT COUNT(*) AS n FROM mailboxes WHERE id = 'helper-mbx'"), 1);
});

test("the purge keeps mail the account wrote in other people's mailboxes", async (t) => {
	const { env, database, count } = await fixture(t);
	database.db.exec(`
		INSERT INTO messages (id, user_id, mailbox_id, direction, from_addr, to_addr, status, created_at) VALUES
			('kept', 'staff', 'owner-mbx', 'outbound', 'owner@one.test', 'x@example.test', 'sent', 1),
			('own', 'staff', 'staff-mbx', 'inbound', 'x@example.test', 'staff@one.test', 'received', 1);
	`);
	assert.equal((await deleteAccounts(env, actor, { ids: ["staff"], transferToId: null })).ok, true);
	database.db.exec(`UPDATE users SET deleted_at = 1 WHERE id = 'staff'`);
	assert.equal(await runAccountRetention(env, new Date()), 1);
	assert.equal(count("SELECT COUNT(*) AS n FROM users WHERE id = 'staff'"), 0);
	assert.equal(database.db.prepare("SELECT user_id FROM messages WHERE id = 'kept'").get().user_id, "owner");
	assert.equal(count("SELECT COUNT(*) AS n FROM messages WHERE id = 'own'"), 0, "the account's own mailbox goes with it");
	assert.equal(count("SELECT COUNT(*) AS n FROM mailboxes WHERE id = 'owner-mbx'"), 1);
});

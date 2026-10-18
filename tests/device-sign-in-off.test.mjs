import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

// Fork hardening: mobile password sign-in skips Turnstile and issues keys that never
// expire, so it is off unless the operator sets DEVICE_SIGN_IN=enabled.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const directory = mkdtempSync(join(root, "node_modules", "mailflare-device-sign-in-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
await build({
	stdin: {
		contents: `
			export { SqliteDatabase } from "./server/runtime/sqlite-database.ts";
			export { applyMigrations } from "./server/runtime/migrate.ts";
			export { POST as deviceSignIn } from "./src/app/api/auth/device/route.ts";
		`,
		resolveDir: root,
		sourcefile: "device-sign-in-test-entry.ts",
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
const { SqliteDatabase, applyMigrations, deviceSignIn } = await import(pathToFileURL(join(directory, "entry.mjs")).href);

async function signIn(t, extraEnv) {
	const database = new SqliteDatabase(":memory:");
	t.after(() => database.db.close());
	await applyMigrations(database, join(root, "drizzle/migrations"));
	globalThis.__mailflareNodeEnv = { DB: database, MAILFLARE_RUNTIME: "node", ...extraEnv };
	t.after(() => { delete globalThis.__mailflareNodeEnv; });
	return deviceSignIn(new Request("https://mailflare.test/api/auth/device", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ email: "nobody@one.test", password: "wrong-password", deviceName: "Phone" }),
	}));
}

test("device sign-in is off by default", async (t) => {
	assert.equal((await signIn(t, {})).status, 404);
});

test("device sign-in checks the password once the operator turns it on", async (t) => {
	assert.equal((await signIn(t, { DEVICE_SIGN_IN: "enabled" })).status, 401);
});

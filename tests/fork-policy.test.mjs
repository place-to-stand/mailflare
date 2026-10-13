import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const directory = mkdtempSync(join(root, "node_modules", "mailflare-fork-policy-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
await build({
	stdin: {
		contents: `
			export * from "./src/lib/licenses/service.ts";
			export { getAccountSeatError } from "./src/lib/licenses/seats.ts";
			export { isTeamMailboxSharingEnabled } from "./src/lib/mailboxes/access-utils.ts";
			export { getLocalLicenseEntitlements } from "./src/lib/licenses/fork-policy.ts";
		`,
		resolveDir: root,
		sourcefile: "fork-policy-test-entry.ts",
	},
	outfile: join(directory, "entry.mjs"),
	bundle: true,
	platform: "node",
	format: "esm",
	target: "node24",
	tsconfig: join(root, "tsconfig.json"),
	packages: "external",
	logLevel: "silent",
});
const policy = await import(pathToFileURL(join(directory, "entry.mjs")).href);
const forbidden = new Proxy({}, { get() { throw new Error("Local features must not read license storage"); } });

test("all upstream entitlements are granted locally with unlimited seats", async () => {
	const entitlements = await policy.getLicenseEntitlements(forbidden);
	assert.equal(entitlements.plan, "team");
	assert.equal(entitlements.accountSeatLimit, null);
	for (const [name, value] of Object.entries(entitlements)) {
		if (name.startsWith("can")) assert.equal(value, true, name);
	}
	// Detect newly added upstream capabilities that the fork policy hasn't covered.
	const types = readFileSync(join(root, "src/lib/licenses/types.d.ts"), "utf8");
	const definition = types.match(/export type LicenseEntitlements = \{([\s\S]*?)\};/)[1];
	for (const match of definition.matchAll(/\b(can\w+)\??:\s*boolean/g)) {
		assert.equal(entitlements[match[1]], true, `New upstream entitlement requires local policy: ${match[1]}`);
	}
	assert.equal(await policy.getAccountSeatError(forbidden), null);
	assert.equal(await policy.isTeamMailboxSharingEnabled(forbidden), true);
});

test("status and legacy activation operations never read storage or contact Paymug", async (t) => {
	t.mock.method(globalThis, "fetch", () => { throw new Error("External activation must not run"); });
	for (const status of [
		await policy.getLicenseStatus(forbidden),
		await policy.activateLicense(forbidden, "", "https://mail.test", "pro"),
		await policy.validateLicense(forbidden, "expired-key", "https://mail.test"),
		await policy.deactivateLicense(forbidden),
	]) {
		assert.equal(status.active, true);
		assert.equal(status.plan, "team");
		assert.equal(status.seatLimit, null);
	}
	assert.equal(globalThis.fetch.mock.callCount(), 0);
});

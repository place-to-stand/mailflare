import { clearClientSessionToken } from "@/lib/auth/client";
import { SETUP_TOKEN_HEADER } from "@/lib/auth/setup-token-utils";
import type {
	DomainSetupResult,
	MxCheckResult,
	RegisterResult,
	SetupPreparationResult,
	SetupStatus,
} from "./types";

const SETUP_TOKEN_STORAGE_KEY = "mailflare.setupToken";

/** The token from /setup?token=…, kept for the tab and taken out of the address bar. */
function getSetupToken(): string {
	const url = new URL(window.location.href);
	const fromUrl = url.searchParams.get("token");
	try {
		if (fromUrl) {
			sessionStorage.setItem(SETUP_TOKEN_STORAGE_KEY, fromUrl);
			url.searchParams.delete("token");
			window.history.replaceState(window.history.state, "", url);
		}
		return fromUrl ?? sessionStorage.getItem(SETUP_TOKEN_STORAGE_KEY) ?? "";
	} catch {
		return fromUrl ?? "";
	}
}

function setupHeaders(json = false): HeadersInit {
	return { ...(json ? { "Content-Type": "application/json" } : {}), [SETUP_TOKEN_HEADER]: getSetupToken() };
}

export async function prepareSetup(): Promise<{ ok: boolean; data: SetupPreparationResult }> {
	const res = await fetch("/api/setup/prepare", { method: "POST", headers: setupHeaders() });
	return {
		ok: res.ok,
		data: (await res.json()) as SetupPreparationResult,
	};
}

export async function getSetupStatus(): Promise<SetupStatus> {
	const res = await fetch("/api/setup/status");
	const data = (await res.json()) as SetupStatus;
	if (!res.ok) throw new Error(data.error ?? "Could not load setup status");
	return data;
}

export async function submitPrimaryDomain(hostname: string): Promise<{ ok: boolean; data: DomainSetupResult }> {
	const res = await fetch("/api/setup/domain", {
		method: "POST",
		headers: setupHeaders(true),
		body: JSON.stringify({ hostname }),
	});

	return {
		ok: res.ok,
		data: (await res.json()) as DomainSetupResult,
	};
}

export async function checkExistingMx(hostname: string): Promise<{ ok: boolean; data: MxCheckResult }> {
	const res = await fetch("/api/setup/domain/mx", {
		method: "POST",
		headers: setupHeaders(true),
		body: JSON.stringify({ hostname }),
	});

	return {
		ok: res.ok,
		data: (await res.json()) as MxCheckResult,
	};
}

export async function submitRegistration(
	form: FormData,
	payload: { firstRun: boolean; domain: string; enableSending?: boolean; replaceMxRecords?: boolean },
): Promise<{ ok: boolean; data: RegisterResult }> {
	const res = await fetch("/api/auth/register", {
		method: "POST",
		headers: setupHeaders(true),
		body: JSON.stringify(
			payload.firstRun
				? {
						domain: payload.domain,
						enableSending: payload.enableSending,
						replaceMxRecords: payload.replaceMxRecords,
						username: form.get("username"),
						password: form.get("password"),
						resetEmail: form.get("resetEmail"),
						turnstileToken: form.get("turnstileToken"),
					}
				: {
						username: form.get("username"),
						password: form.get("password"),
						resetEmail: form.get("resetEmail"),
						turnstileToken: form.get("turnstileToken"),
					},
		),
	});

	const data = (await res.json()) as RegisterResult;
	if (res.ok) {
		clearClientSessionToken();
		try {
			sessionStorage.removeItem(SETUP_TOKEN_STORAGE_KEY);
		} catch {
			// Storage can be unavailable; the token then only lived in this page's URL.
		}
	}
	return { ok: res.ok, data };
}

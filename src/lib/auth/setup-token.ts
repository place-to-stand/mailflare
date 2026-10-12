import { NextResponse } from "next/server";
import { SETUP_TOKEN_HEADER } from "@/lib/auth/setup-token-utils";
import { timingSafeEqual } from "@/lib/auth/totp";

/**
 * First-run setup makes the caller primary admin and lets them point any zone
 * CF_TOKEN can see at Mailflare (MX replacement included), so it must not be
 * open to whoever reaches a fresh deploy first. The operator sets the
 * SETUP_TOKEN secret and opens /setup?token=<value>; without the secret
 * configured, setup stays closed.
 */
export function hasValidSetupToken(env: CloudflareEnv, request: Request): boolean {
	const expected = env.SETUP_TOKEN?.trim();
	const provided = request.headers.get(SETUP_TOKEN_HEADER)?.trim();
	return !!expected && !!provided && timingSafeEqual(provided, expected);
}

export function setupTokenRequiredResponse(env: CloudflareEnv) {
	const error = env.SETUP_TOKEN?.trim()
		? "Open this page with the setup token: /setup?token=<SETUP_TOKEN>"
		: "Set the SETUP_TOKEN Worker secret, then open /setup?token=<SETUP_TOKEN>";
	return NextResponse.json({ error }, { status: 403 });
}

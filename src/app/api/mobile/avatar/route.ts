import { NextResponse } from "next/server";
import { getEnv } from "@/lib/cloudflare";
import { authenticateApiRequest, hasScope } from "@/lib/api/key-auth";
import { getAvatarImageResponse } from "@/lib/avatar-images";

/**
 * The signed-in user's profile picture for the mobile app. `GET /api/profile/avatar`
 * needs a session cookie, which a device key is not, so this takes the same
 * `jmap`-scoped key the app uses everywhere else. `?variant=preview` is the small one.
 */
export async function GET(request: Request) {
	const env = getEnv();
	const auth = await authenticateApiRequest(env, request);
	if (!auth) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
	if (!hasScope(auth.scopes, "jmap")) return NextResponse.json({ error: "This key does not have the jmap scope" }, { status: 403 });
	if (!auth.user.avatarKey) return new Response("Not found", { status: 404 });
	return getAvatarImageResponse(request, env.BUCKET, auth.user.avatarKey);
}

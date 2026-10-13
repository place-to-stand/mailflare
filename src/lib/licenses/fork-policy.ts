import type { LicenseEntitlements, LicenseStatus } from "./types";

// Fork policy: keep upstream interfaces for easy merges, but grant every feature
// locally without license records, keys, seat limits, or external activation.
export const LOCAL_FEATURES_ENABLED = true;

export function getLocalLicenseStatus(): LicenseStatus {
	return {
		plan: "team",
		state: "active",
		features: [],
		seatLimit: null,
		instanceId: "local-fork",
		instanceUrl: null,
		active: true,
		activatedAt: null,
		validatedAt: null,
	};
}

export function getLocalLicenseEntitlements(): LicenseEntitlements {
	return {
		plan: "team",
		canCustomizeBranding: true,
		canManageAccounts: true,
		canShareMailboxes: true,
		accountSeatLimit: null,
		canForwardEmail: true,
	};
}

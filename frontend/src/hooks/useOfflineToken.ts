/**
 * Zero-Knowledge Offline Token helpers.
 *
 * The JWT payload is decoded locally (base64url decode of the middle segment)
 * to check expiry — no server call needed, no signing secret ever sent to the
 * client.  Revocation requires an online call to /verify-offline-token.
 */

const STORAGE_KEY = (invoiceId: string) => `offline_token_${invoiceId}`;

export interface OfflineTokenStatus {
    isValid: boolean;
    reason?: 'no_token' | 'expired' | 'parse_error';
    hoursRemaining?: number;
    expiresAt?: Date;
}

/** Decode the JWT payload without verifying the signature. */
function decodePayload(token: string): Record<string, unknown> | null {
    try {
        const segment = token.split('.')[1];
        // Restore standard base64 from base64url
        const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
        return JSON.parse(atob(b64));
    } catch {
        return null;
    }
}

/**
 * Check the locally-stored offline token for `invoiceId`.
 * This is a pure client-side check — no network request.
 */
export function getOfflineTokenStatus(invoiceId: string): OfflineTokenStatus {
    const token = localStorage.getItem(STORAGE_KEY(invoiceId));
    if (!token) return { isValid: false, reason: 'no_token' };

    const payload = decodePayload(token);
    if (!payload || typeof payload.exp !== 'number') {
        return { isValid: false, reason: 'parse_error' };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp <= nowSec) return { isValid: false, reason: 'expired' };

    const hoursRemaining = Math.floor((payload.exp - nowSec) / 3600);
    return {
        isValid: true,
        hoursRemaining,
        expiresAt: new Date(payload.exp * 1000),
    };
}

/** Persist a JWT received from the admin into localStorage. */
export function storeOfflineToken(invoiceId: string, token: string): void {
    localStorage.setItem(STORAGE_KEY(invoiceId), token);
}

/** Remove the stored offline token for `invoiceId`. */
export function clearOfflineToken(invoiceId: string): void {
    localStorage.removeItem(STORAGE_KEY(invoiceId));
}

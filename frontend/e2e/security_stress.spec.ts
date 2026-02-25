import { test, expect } from '@playwright/test';

// Inject a valid auth cookie before each test
test.beforeEach(async ({ page }) => {
  await page.context().addCookies([{
    name: 'auth_token',
    value: 'stress_test_token',
    domain: 'localhost',
    path: '/',
  }]);
});

// ─────────────────────────────────────────────────────────────
//  1. DOM INSPECTION — No raw media tags
// ─────────────────────────────────────────────────────────────

test.describe('DOM Inspection — No raw content leakage', () => {
  test('dashboard contains no <img> tags with raw content src', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    const imgTags = await page.locator('img').all();
    for (const img of imgTags) {
      const src = await img.getAttribute('src') ?? '';
      // Raw decrypted content would be a data URI (data:image/...) or blob
      expect(src).not.toMatch(/^data:image\//i);
      expect(src).not.toMatch(/^blob:/i);
    }
  });

  test('dashboard contains no <video> tags exposing raw stream', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    const videoTags = await page.locator('video').all();
    for (const video of videoTags) {
      const src = await video.getAttribute('src') ?? '';
      expect(src).not.toMatch(/^blob:/i);
      expect(src).not.toMatch(/^http:\/\/localhost:8000/i);
    }
    // Content must be rendered on canvas (Wasm), not via <video>
    const canvas = page.locator('canvas');
    await expect(canvas).toBeVisible({ timeout: 10_000 });
  });

  test('right-click context menu is disabled on canvas', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForSelector('canvas', { timeout: 10_000 });

    // Trigger contextmenu event and verify it was prevented.
    // We must check event.defaultPrevented AFTER dispatchEvent() returns —
    // React attaches its handler via event delegation at the root, so it runs
    // during the bubble phase, after any listener added directly on the canvas.
    // dispatchEvent() is synchronous and returns only after all handlers complete.
    const prevented = await page.evaluate(() => {
      const canvas = document.querySelector('canvas');
      if (!canvas) return false;
      const event = new MouseEvent('contextmenu', { bubbles: true, cancelable: true });
      canvas.dispatchEvent(event);
      return event.defaultPrevented;
    });
    expect(prevented).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────
//  2. WASM MEMORY — Fingerprint wiped after sign out
// ─────────────────────────────────────────────────────────────

test.describe('Wasm Memory — Session cleanup', () => {
  test('localStorage is cleared after sign out', async ({ page }) => {
    // Seed localStorage with a fake session
    await page.goto('/dashboard');
    await page.evaluate(() => {
      localStorage.setItem('auth_token', 'fake_token_xyz');
      localStorage.setItem('invoice_id', 'INV-MEMORY-TEST');
    });

    // Mock the backend signout call
    await page.route('**/signout**', (route) =>
      route.fulfill({ status: 200, body: '{"status":"signed_out"}' })
    );

    // evaluate(el.click()) invokes the native DOM click in the browser JS
    // context, bypassing the Next.js dev-mode overlay (<nextjs-portal>).
    await page.getByRole('button', { name: /sign out/i }).evaluate(el => (el as HTMLElement).click());
    await page.waitForURL(/\/auth\/signin/);

    // Navigate back and verify storage is empty
    await page.goto('/dashboard');
    const authToken  = await page.evaluate(() => localStorage.getItem('auth_token'));
    const invoiceId  = await page.evaluate(() => localStorage.getItem('invoice_id'));
    expect(authToken).toBeNull();
    expect(invoiceId).toBeNull();
  });

  test('auth cookie is cleared after sign out', async ({ page }) => {
    await page.goto('/dashboard');

    await page.route('**/signout**', (route) =>
      route.fulfill({ status: 200, body: '{"status":"signed_out"}' })
    );

    await page.getByRole('button', { name: /sign out/i }).evaluate(el => (el as HTMLElement).click());
    await page.waitForURL(/\/auth\/signin/);

    const cookies = await page.context().cookies();
    const authCookie = cookies.find((c) => c.name === 'auth_token');
    expect(authCookie).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────
//  3. ROUTE HARDENING — Middleware blocks all protected paths
// ─────────────────────────────────────────────────────────────

test.describe('Route Hardening — Unauthenticated access', () => {
  test('all protected routes redirect without cookie', async ({ page }) => {
    await page.context().clearCookies();

    for (const route of ['/dashboard', '/admin', '/viewer']) {
      await page.goto(route);
      await expect(page).toHaveURL(/\/auth\/signin/, { timeout: 5_000 });
    }
  });
});

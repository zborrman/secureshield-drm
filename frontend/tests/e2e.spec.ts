import { test, expect } from '@playwright/test';

// ─────────────────────────────────────────────────────────────
//  AUTH FLOW
// ─────────────────────────────────────────────────────────────

test.describe('Sign In Page', () => {
  test('renders all required fields', async ({ page }) => {
    await page.goto('/auth/signin');

    await expect(page.getByText('Access Portal')).toBeVisible();
    await expect(page.getByPlaceholder('INV-2026-XYS')).toBeVisible();
    await expect(page.getByPlaceholder('••••••••••••••••')).toBeVisible();
    await expect(page.getByRole('button', { name: /activate secure session/i })).toBeVisible();
  });

  test('shows error on invalid credentials', async ({ page }) => {
    await page.goto('/auth/signin');

    page.on('dialog', async (dialog) => {
      expect(dialog.message()).toContain('Ошибка доступа');
      await dialog.dismiss();
    });

    await page.getByPlaceholder('INV-2026-XYS').fill('INVALID-INV');
    await page.getByPlaceholder('••••••••••••••••').fill('wrong-key');
    await page.getByRole('button', { name: /activate secure session/i }).click();
  });
});

// ─────────────────────────────────────────────────────────────
//  ROUTE PROTECTION (Middleware)
// ─────────────────────────────────────────────────────────────

test.describe('Middleware — Route Protection', () => {
  test('redirects unauthenticated user from /dashboard to /auth/signin', async ({ page }) => {
    // Clear all cookies and storage to ensure no session exists
    await page.context().clearCookies();
    await page.goto('/dashboard');

    await expect(page).toHaveURL(/\/auth\/signin/);
  });

  test('redirects unauthenticated user from /admin to /auth/signin', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/admin');

    await expect(page).toHaveURL(/\/auth\/signin/);
  });

  test('redirects unauthenticated user from /viewer to /auth/signin', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/viewer');

    await expect(page).toHaveURL(/\/auth\/signin/);
  });
});

// ─────────────────────────────────────────────────────────────
//  DASHBOARD (requires authenticated session)
// ─────────────────────────────────────────────────────────────

test.describe('Dashboard — Authenticated Session', () => {
  test.beforeEach(async ({ page }) => {
    // Inject auth cookie to simulate a valid session
    await page.context().addCookies([{
      name: 'auth_token',
      value: 'test_session_token',
      domain: 'localhost',
      path: '/',
    }]);
  });

  test('renders sidebar navigation', async ({ page }) => {
    await page.goto('/dashboard');

    await expect(page.getByText('SECURESHIELD')).toBeVisible();
    await expect(page.getByRole('link', { name: /dashboard/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /secure viewer/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /admin console/i })).toBeVisible();
  });

  test('renders Secure Content Viewer heading', async ({ page }) => {
    await page.goto('/dashboard');

    await expect(page.getByText('Secure Content Viewer')).toBeVisible();
  });

  test('renders canvas element for Wasm player', async ({ page }) => {
    await page.goto('/dashboard');

    // Wait for Wasm dynamic import to complete
    await page.waitForSelector('canvas', { timeout: 10_000 });
    const canvas = page.locator('canvas');
    await expect(canvas).toBeVisible();
  });

  test('notification bell is visible in header', async ({ page }) => {
    await page.goto('/dashboard');

    // Bell SVG icon is inside the NotificationCenter button
    const bellButton = page.locator('header button').first();
    await expect(bellButton).toBeVisible();
  });

  test('sign out button clears session and redirects', async ({ page }) => {
    await page.goto('/dashboard');

    // Mock the backend signout call
    await page.route('**/signout**', (route) => route.fulfill({ status: 200, body: '{"status":"signed_out"}' }));

    // force:true bypasses Next.js dev-mode overlay (<nextjs-portal>) which
    // intercepts pointer events in Firefox without blocking the real button.
    await page.getByRole('button', { name: /sign out/i }).click({ force: true });
    await expect(page).toHaveURL(/\/auth\/signin/);
  });
});

// ─────────────────────────────────────────────────────────────
//  INFRASTRUCTURE STATUS
// ─────────────────────────────────────────────────────────────

test.describe('StatusIndicator', () => {
  test.beforeEach(async ({ page }) => {
    await page.context().addCookies([{
      name: 'auth_token',
      value: 'test_session_token',
      domain: 'localhost',
      path: '/',
    }]);
  });

  test('shows online when backend health check passes', async ({ page }) => {
    await page.route('**/health', (route) =>
      route.fulfill({ status: 200, body: JSON.stringify({ status: 'healthy', database: 'connected' }) })
    );

    await page.goto('/dashboard');

    await expect(page.getByText(/api.*online/i)).toBeVisible({ timeout: 5_000 });
  });

  test('shows offline when backend is unreachable', async ({ page }) => {
    await page.route('**/health', (route) => route.abort());

    await page.goto('/dashboard');

    // Both "API: offline" and "PostgreSQL: offline" match — use first() to
    // satisfy Playwright's strict-mode requirement of a single element.
    await expect(page.getByText(/offline/i).first()).toBeVisible({ timeout: 5_000 });
  });
});

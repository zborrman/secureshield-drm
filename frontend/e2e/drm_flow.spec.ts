import { test, expect } from '@playwright/test';

test('Full DRM User Journey', async ({ page }) => {
  // Mock verify-license so the test doesn't depend on a seeded CI database.
  // Return 401 for unknown credentials and 200 for the known test credentials.
  await page.route('**/verify-license', async (route) => {
    const body = JSON.parse(route.request().postData() ?? '{}');
    if (body.invoice_id === 'TEST-INV-001') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ session_token: 'test-session-token-ci' }),
      });
    } else {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Invalid credentials' }),
      });
    }
  });

  // 1. Navigate to Sign-In
  await page.goto('http://localhost:3000/auth/signin');

  // 2. Test Error Handling: Login with non-existent ID
  await page.fill('input[placeholder="INV-2026-XYS"]', 'INVALID_ID');
  await page.fill('input[type="password"]', 'ANY_KEY');

  // The signin page uses alert() — intercept dialog before clicking
  page.once('dialog', async (dialog) => {
    await expect(dialog.message()).toContain('Ошибка доступа');
    await dialog.dismiss();
  });

  await page.click('button:has-text("Activate Secure Session")');

  // 3. Test Success Logic
  await page.fill('input[placeholder="INV-2026-XYS"]', 'TEST-INV-001');
  await page.fill('input[type="password"]', 'SK-TEST_KEY_123');
  await page.click('button:has-text("Activate Secure Session")');

  // 4. Verify redirect to dashboard
  await expect(page).toHaveURL(/.*dashboard/);
  await expect(page.locator('h1:has-text("Secure Content Viewer")')).toBeVisible();
});

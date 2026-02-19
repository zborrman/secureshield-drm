import { test, expect } from '@playwright/test';

test('Full DRM User Journey', async ({ page }) => {
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

  // 3. Test Success Logic (assuming a test key exists in DB)
  await page.fill('input[placeholder="INV-2026-XYS"]', 'TEST-INV-001');
  await page.fill('input[type="password"]', 'SK-TEST_KEY_123');
  await page.click('button:has-text("Activate Secure Session")');

  // 4. Verify Wasm Enclave Activation
  await expect(page).toHaveURL(/.*dashboard/);
  await expect(page.locator('text=Wasm Enclave Active')).toBeVisible();
});

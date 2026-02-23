use wasm_bindgen::prelude::*;

// Упрощенный пример "соли" для хеширования, скрытой в бинарнике
const HIDDEN_SALT: u32 = 0xDEADC0DE;

#[wasm_bindgen]
pub struct SecureViewer {
    is_verified: bool,
}

#[wasm_bindgen]
impl SecureViewer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { is_verified: false }
    }

    /// Проверка ключа с использованием побитовых операций,
    /// которые сложно восстановить после компиляции.
    #[wasm_bindgen]
    pub fn verify_key(&mut self, input_key: &str) -> bool {
        let mut hash: u32 = 0;
        for (i, c) in input_key.chars().enumerate() {
            hash = hash.wrapping_add(c as u32 ^ (HIDDEN_SALT >> (i % 4)));
        }

        // Допустим, правильный хеш для нашего ключа — 12345678 (пример)
        self.is_verified = hash == 0x75BCD15;
        self.is_verified
    }

    /// Накладывает динамический шум, мешающий записи экрана.
    /// Вызывайте это в каждом кадре анимации.
    #[wasm_bindgen]
    pub fn apply_anti_capture_noise(&self, mut pixels: Vec<u8>, seed: u8) -> Vec<u8> {
        if !self.is_verified { return pixels; }

        for i in (0..pixels.len()).step_by(4) {
            // Слегка меняем яркость каждого пикселя в зависимости от "seed" (времени)
            // Изменение на 1-2 единицы невидимо глазу, но портит хэш кадра для захватчиков
            let noise = (seed % 3) as i16 - 1;

            pixels[i] = (pixels[i] as i16 + noise).clamp(0, 255) as u8;     // R
            pixels[i+1] = (pixels[i+1] as i16 - noise).clamp(0, 255) as u8; // G
        }
        pixels
    }

    /// Функция "Controlled Viewing": дешифрует данные только если ключ прошел проверку.
    #[wasm_bindgen]
    pub fn decrypt_content(&self, encrypted_data: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        decrypt_inner(self.is_verified, encrypted_data)
            .map_err(JsValue::from_str)
    }
}

/// Platform-neutral core of decrypt_content.
///
/// Returns `Err(&str)` instead of `Err(JsValue)` so that native unit tests
/// can call this without hitting the wasm-bindgen JsValue panic.
/// The public #[wasm_bindgen] method wraps this and converts the error.
fn decrypt_inner(is_verified: bool, encrypted_data: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if !is_verified {
        return Err("ACCESS_DENIED_SECURE_ENCLAVE");
    }
    // XOR-дешифровка (placeholder — в продакшне AES-GCM)
    Ok(encrypted_data.iter().map(|&b| b ^ 0xFF).collect())
}

// ─────────────────────────────────────────────
//  Unit Tests (run with: cargo test)
// ─────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // ── decrypt_content ──────────────────────

    #[test]
    fn test_decrypt_denied_when_unverified() {
        // Use decrypt_inner directly: calling viewer.decrypt_content() on non-wasm32
        // would trigger JsValue::from_str() which panics outside the browser.
        let result = decrypt_inner(false, vec![0xFF, 0xAA]);
        assert!(result.is_err(), "Unverified viewer must not decrypt");
        assert_eq!(result.unwrap_err(), "ACCESS_DENIED_SECURE_ENCLAVE");
    }

    #[test]
    fn test_decrypt_xor_correctness() {
        let viewer = SecureViewer { is_verified: true };
        let data = vec![0xFF, 0xAB, 0x00];
        let decrypted = viewer.decrypt_content(data).unwrap();
        // XOR with 0xFF: 0xFF^0xFF=0x00, 0xAB^0xFF=0x54, 0x00^0xFF=0xFF
        assert_eq!(decrypted, vec![0x00, 0x54, 0xFF]);
    }

    #[test]
    fn test_decrypt_roundtrip() {
        let viewer = SecureViewer { is_verified: true };
        let original = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
        let encrypted = viewer.decrypt_content(original.clone()).unwrap();
        let restored = SecureViewer { is_verified: true }
            .decrypt_content(encrypted)
            .unwrap();
        assert_eq!(restored, original, "XOR must be its own inverse");
    }

    // ── apply_anti_capture_noise ─────────────

    #[test]
    fn test_noise_blocked_when_unverified() {
        let viewer = SecureViewer::new();
        let pixels = vec![100u8, 100, 100, 255];
        let result = viewer.apply_anti_capture_noise(pixels.clone(), 5);
        assert_eq!(result, pixels, "Pixels must be unchanged for unverified viewer");
    }

    #[test]
    fn test_noise_preserves_pixel_count() {
        let viewer = SecureViewer { is_verified: true };
        let pixels = vec![100u8, 200, 150, 255, 80, 80, 80, 255];
        let result = viewer.apply_anti_capture_noise(pixels.clone(), 1);
        assert_eq!(result.len(), pixels.len());
    }

    #[test]
    fn test_noise_modifies_rg_channels_only() {
        // seed=0 → noise = (0%3) as i16 - 1 = -1
        // R = pixel - 1, G = pixel + 1, B unchanged, A unchanged
        let viewer = SecureViewer { is_verified: true };
        let pixels = vec![100u8, 100, 100, 255];
        let result = viewer.apply_anti_capture_noise(pixels, 0);
        assert_eq!(result[0], 99,  "R channel: 100 + (-1) = 99");
        assert_eq!(result[1], 101, "G channel: 100 - (-1) = 101");
        assert_eq!(result[2], 100, "B channel: unchanged");
        assert_eq!(result[3], 255, "A channel: unchanged");
    }

    #[test]
    fn test_noise_clamps_at_boundaries() {
        let viewer = SecureViewer { is_verified: true };
        // seed=2 → noise = (2%3) as i16 - 1 = 1 → R = pixel+1, G = pixel-1
        let pixels = vec![255u8, 0, 128, 255]; // R at max, G at min
        let result = viewer.apply_anti_capture_noise(pixels, 2);
        assert_eq!(result[0], 255, "R must clamp at 255");
        assert_eq!(result[1], 0,   "G must clamp at 0");
    }
}

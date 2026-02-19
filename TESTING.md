# SecureShield — Инструкция по запуску тестов

> Все команды для **Windows PowerShell**. Открывайте терминал в папке проекта.

---

## Шаг 1 — Запустить Docker

```powershell
docker-compose down
docker-compose up -d
```

Проверить что контейнеры работают:
```powershell
docker-compose ps
```

Ожидаемый результат:
```
NAME               STATUS
secureshield_db    Up (healthy)
secureshield_api   Up
```

Если `secureshield_api` не запускается — порт занят:
```powershell
netstat -ano | findstr :8000
# Найти PID в последней колонке, затем:
taskkill /PID <PID> /F
docker-compose up -d
```

---

## Шаг 2 — Backend тесты (Pytest)

```powershell
docker-compose exec backend pytest tests/ test_security.py -v
```

Ожидаемый результат:
```
PASSED tests/test_main.py::test_security_workflow
PASSED tests/test_penetration.py::test_admin_route_rejects_missing_key[...]
PASSED tests/test_penetration.py::test_sql_injection_in_verify
PASSED tests/test_audit.py::test_health_returns_correct_json
PASSED tests/test_audit.py::test_signout_creates_audit_entry
PASSED tests/test_audit.py::test_admin_audit_log_records_verify_attempts
PASSED tests/test_audit.py::test_admin_alerts_shows_recent_failures
PASSED test_security.py::test_full_license_lifecycle
PASSED test_security.py::test_brute_force_protection
18 passed
```

---

## Шаг 3 — Rust / Wasm тесты

Сначала проверить что Rust установлен:
```powershell
cargo --version
```

Если не установлен — скачать с https://rustup.rs и установить, затем перезапустить терминал.

Запустить тесты:
```powershell
cd wasm
cargo test
cd ..
```

Ожидаемый результат:
```
test tests::test_decrypt_denied_when_unverified ... ok
test tests::test_decrypt_xor_correctness ... ok
test tests::test_decrypt_roundtrip ... ok
test tests::test_noise_blocked_when_unverified ... ok
test tests::test_noise_preserves_pixel_count ... ok
test tests::test_noise_modifies_rg_channels_only ... ok
test tests::test_noise_clamps_at_boundaries ... ok
7 passed
```

---

## Шаг 4 — E2E тесты (Playwright)

### Установка (один раз)

```powershell
cd frontend
npm install
npx playwright install chromium
cd ..
```

### Запуск (фронтенд должен работать)

```powershell
docker-compose up -d
cd frontend
npm run test:e2e
cd ..
```

### Запуск с визуальным интерфейсом (видно браузер)

```powershell
cd frontend
npm run test:e2e:ui
cd ..
```

---

## Запуск всех тестов по порядку

Скопируйте и выполните блок целиком в PowerShell:

```powershell
# 1. Docker
docker-compose down
docker-compose up -d
Start-Sleep -Seconds 5

# 2. Backend
docker-compose exec backend pytest tests/ test_security.py -v

# 3. Rust
cd wasm
cargo test
cd ..

# 4. Playwright
cd frontend
npm run test:e2e
cd ..
```

---

## Таблица тестов

| # | Тест | Инструмент | Команда |
|---|---|---|---|
| 1 | Жизненный цикл лицензии | Pytest | `docker-compose exec backend pytest test_security.py -v` |
| 2 | Brute-force защита | Pytest | `docker-compose exec backend pytest test_security.py -v` |
| 3 | Хеширование ключа в БД | Pytest | `docker-compose exec backend pytest tests/test_main.py -v` |
| 4 | SQL-инъекции | Pytest | `docker-compose exec backend pytest tests/test_penetration.py -v` |
| 5 | Admin 401 без ключа | Pytest | `docker-compose exec backend pytest tests/test_penetration.py -v` |
| 6 | Health JSON формат | Pytest | `docker-compose exec backend pytest tests/test_audit.py -v` |
| 7 | Signout пишет в AuditLog | Pytest | `docker-compose exec backend pytest tests/test_audit.py -v` |
| 8 | Audit-log фиксирует попытки | Pytest | `docker-compose exec backend pytest tests/test_audit.py -v` |
| 9 | Alerts находит свежие ошибки | Pytest | `docker-compose exec backend pytest tests/test_audit.py -v` |
| 10 | XOR расшифровка | Cargo | `cd wasm; cargo test` |
| 11 | Анти-захват пикселей | Cargo | `cd wasm; cargo test` |
| 12 | Защита роутов (middleware) | Playwright | `cd frontend; npm run test:e2e` |
| 13 | DOM без `<video>/<img>` | Playwright | `cd frontend; npm run test:e2e` |
| 14 | Очистка памяти при выходе | Playwright | `cd frontend; npm run test:e2e` |

---

## Частые ошибки

| Ошибка | Решение |
|---|---|
| `service "backend" is not running` | `docker-compose up -d` |
| `port is already allocated` | `docker-compose down` затем `docker-compose up -d` |
| `'&&' is not valid` | В PowerShell использовать `;` или отдельные строки |
| `cargo: not found` | Установить Rust с rustup.rs |
| `playwright: not found` | `cd frontend; npm install` |
| `14 failed - async_generator` | Контейнер собран со старым conftest.py — `docker-compose up -d --build backend` |

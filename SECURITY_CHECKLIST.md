# Единый универсальный чек-лист безопасности для Vibe-кодинга (AI-Generated Code)

> **Назначение:** Используйте этот список двумя способами:
> 1. **Системный промпт** — вставьте перед началом работы с ИИ, чтобы он учитывал все требования с первой строки кода.
> 2. **Лист проверки перед релизом** — пройдитесь по каждому пункту вручную до того, как проект увидят первые пользователи.

---

## Блок 1 — Секреты и Инфраструктура

*Нейросети часто пишут код так, будто он всегда будет запущен локально. Эти пункты устраняют наиболее опасные инфраструктурные упущения.*

- [ ] **1. Secrets Management**
  `.env`, `node_modules/`, `venv/` и любые файлы с ключами сервисов (AWS, Stripe, OpenAI и др.) добавлены в `.gitignore` **до первого коммита**. В истории git нет ни одного секрета.

- [ ] **2. No API Key Leaks**
  Во фронтенд-коде (React, Vue, Next.js client-side) отсутствует хардкод `sk-...`, `nvapi-...` или любого `API_KEY`. Все вызовы к сторонним платным API идут **исключительно через бэкенд-прокси**.

- [ ] **3. HTTPS Enforcement**
  Сервер перенаправляет HTTP → HTTPS. Куки сессий (и токены) выставлены с флагами `Secure`, `HttpOnly`, `SameSite=Strict`.

- [ ] **4. Dependency Audit**
  Зависимости проверены через `npm audit` / `pip-audit` / `trivy`. ИИ нередко «галлюцинирует» устаревшими версиями пакетов с известными CVE — это нужно проверять явно.

---

## Блок 2 — Защита данных и Базы данных

*ИИ любит писать логику работы с данными напрямую, пропуская валидацию и параметризацию.*

- [ ] **5. Input Validation**
  Все данные от пользователя проходят через строгую схему (Pydantic, Zod, Joi) **прежде чем попасть в бизнес-логику**. Нет «голых» `request.json` без валидации типов и диапазонов.

- [ ] **6. SQL Injection Prevention**
  Запросы к БД написаны только через ORM (SQLAlchemy, Prisma, TypeORM) или с параметризованными запросами (`?`, `:param`). Нет f-строк, конкатенации или `.format()` в SQL.

- [ ] **7. XSS Prevention**
  Фронтенд экранирует весь пользовательский контент перед рендерингом. Использование `dangerouslySetInnerHTML` / `.innerHTML` запрещено или проходит явный аудит + санитизацию (DOMPurify).

- [ ] **8. Database Indexes**
  На полях, по которым идёт поиск или JOIN (`email`, `user_id`, `license_key`, `status`, `created_at`), выставлены индексы. Без них проект упадёт от таймаутов при первых 1 000+ записях.

---

## Блок 3 — Идентификация и Доступ

*Базовый логин ИИ пишет сносно — но восстановление пароля и ролевая модель регулярно выходят небезопасными.*

- [ ] **9. Auth & Authorization (RBAC)**
  Пароли хранятся только в виде хэшей (Bcrypt / Argon2 — никакого MD5/SHA1). На каждом защищённом эндпоинте стоят два слоя middleware: проверка токена (JWT / Session) **и** проверка роли (RBAC).

- [ ] **10. Secure Password Reset**
  Восстановление пароля работает через одноразовые токены с коротким TTL (≤ 15 мин). Ответ на запрос сброса **не раскрывает**, зарегистрирован ли такой email (защита от user enumeration).

---

## Блок 4 — Устойчивость сети и API

*Боты, парсеры и злоумышленники сжигают серверный бюджет в первые же дни — особенно если открыты LLM-эндпоинты.*

- [ ] **11. Rate Limiting**
  На всех эндпоинтах (особенно `/login`, `/register`, `/reset-password`, любые вызовы LLM) стоит лимитер: например, ≤ 100 запросов / 15 мин с одного IP. Превышение → `429 Too Many Requests`.

- [ ] **12. CORS & Security Headers**
  `Helmet` (Node) или аналоги (FastAPI `SecurityHeadersMiddleware`) подключены. CORS ограничен конкретным доменом фронтенда — никакого `Access-Control-Allow-Origin: *` в продакшене. Выставлены CSP, HSTS, X-Frame-Options, X-Content-Type-Options.

---

## Блок 5 — Мониторинг и Отказоустойчивость

*Ошибки неизбежны. Задача — чтобы они не раскрывали архитектуру и фиксировались для разбора.*

- [ ] **13. Global Error Handling**
  Бэкенд обёрнут в глобальный `ErrorHandler` / middleware. Пользователь получает только стандартный ответ (`500 Internal Server Error`) — никаких `stack trace`, путей к файлам и SQL-запросов в теле ответа.

- [ ] **14. Structured Logging**
  Вместо `console.log` / `print` используется профессиональный логгер (Winston, Pino, Python `logging`). Логи пишутся в файл или систему мониторинга. Пароли, токены и ключи **маскируются** в логах перед записью.

---

## Быстрый старт: системный промпт для ИИ

Вставьте этот блок в начало чата с Cursor / ChatGPT / Claude перед постановкой задачи:

```
Before writing any code, apply the following security checklist to every
decision you make:

1. Never hardcode secrets — use environment variables. Add .env to .gitignore
   before the first commit.
2. Never expose API keys in frontend code. All third-party API calls go
   through a backend proxy.
3. Enforce HTTPS. Set cookies with Secure, HttpOnly, SameSite=Strict.
4. Validate all user input with a strict schema (Pydantic / Zod / Joi)
   before it touches business logic.
5. Use ORM or parameterized queries only. Never concatenate user data into SQL.
6. Sanitize all user content before rendering. No dangerouslySetInnerHTML
   without DOMPurify.
7. Add database indexes on every field used in WHERE or JOIN clauses.
8. Hash passwords with Bcrypt or Argon2. Never MD5 or SHA1.
9. Protect every endpoint with token verification AND role check (RBAC).
10. Password reset must use short-TTL one-time tokens and must not reveal
    whether the email exists.
11. Apply rate limiting on all endpoints, especially /login and any LLM calls.
12. Use Helmet / SecurityHeadersMiddleware. Restrict CORS to the frontend
    domain only — never wildcard in production.
13. Wrap all backend handlers in a global ErrorHandler. Never expose stack
    traces or internal paths to the client.
14. Use a structured logger (Winston / Pino / Python logging). Mask passwords
    and tokens in all log output.
```

---

## Применение в работе с клиентами (SMB)

Передавайте этот чек-лист клиентам с формулировкой:

> *«Если вы создали приложение с помощью Cursor или ChatGPT —
> пройдитесь по этим 14 пунктам до того, как привлечёте первых пользователей.
> Каждый незакрытый пункт — это либо утечка данных, либо выгоревший бюджет на API, либо штраф по GDPR.»*

---

*Версия 1.0 · SecureShield DRM System · 2026*

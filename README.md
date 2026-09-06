# Secure QR Auth — Cloudflare Worker

Версия под новый Cloudflare Workers Builds: один Worker обслуживает `/api/*`, а Vite-сборка из `dist/` разворачивается как Worker Static Assets.

## Что происходит

- На главной есть `Зарегистрироваться` и QR для входа.
- QR одноразовый и автоматически меняется каждые 120 секунд.
- При регистрации пользователь вводит ник и пароль.
- Пароль не отправляется на Worker и не хранится в D1.
- Браузер создаёт ECDSA P-256 ключ устройства. Private key локально шифруется AES-GCM ключом, полученным из пароля через PBKDF2-SHA-256 (600 000 итераций).
- После регистрации устройство становится доверенным и видит `Открыть камеру для QR` и `Выйти`.
- Доверенное устройство сканирует QR другого устройства и вводит пароль локально.
- Если пароль открыл local private key, устройство подписывает одноразовый challenge.
- Worker получает только подпись и проверяет её public key устройства.
- Устройство, которое показывало QR, получает HttpOnly-сессию. Аккаунт на сканирующем устройстве не меняется.

## Структура GitHub

Загружать:

- `worker/`
- `src/`
- `public/`
- `index.html`
- `package.json`
- `package-lock.json` (после `npm install`)
- `wrangler.jsonc`
- `schema.sql`
- `.gitignore`
- `.dev.vars.example`
- `.node-version`
- `README.md`

НЕ загружать:

- `.dev.vars`
- `.env` / `.env.*`
- `node_modules/`
- `dist/`
- `.wrangler/`
- Cloudflare API tokens
- настоящий `LOGIN_HMAC_KEY`

## Cloudflare Workers Builds

В Cloudflare при подключении GitHub:

- Build command: `npm run build`
- Deploy command: `npx wrangler deploy`
- `Protect with Cloudflare Access`: выключено

`wrangler.jsonc` уже содержит Worker entrypoint, Static Assets и binding `DB`.

### D1

В `wrangler.jsonc` D1 объявлена только как:

```jsonc
"d1_databases": [
  { "binding": "DB" }
]
```

Современный Wrangler умеет автоматически provision D1 resource при deploy, если binding указан без ID. Для новой тестовой установки вручную создавать DB не обязательно.

Кроме того Worker лениво создаёт нужные таблицы через `CREATE TABLE IF NOT EXISTS` при первом API-запросе. `schema.sql` оставлен как документ схемы и для будущих миграций.

### LOGIN_HMAC_KEY

После первого deploy откройте Worker -> Settings -> Variables and secrets и добавьте encrypted secret:

`LOGIN_HMAC_KEY`

Сгенерировать можно:

```bash
openssl rand -hex 32
```

Никогда не помещайте реальное значение в GitHub.

После добавления secret сделайте новый deployment или redeploy.

## Важно про имя Worker

В `wrangler.jsonc` сейчас:

```jsonc
"name": "newtest"
```

Это сделано под текущий Worker `newtest`. Если проект Cloudflare называется иначе, поменяйте только это значение на имя вашего Worker.

## Локальный запуск

```bash
npm install
npm run dev
```

Для локального секрета скопируйте `.dev.vars.example` в `.dev.vars` и замените значение.

## Ограничение этой версии

Устройство, которое вошло по QR, получает сессию, но не становится доверенным автоматически. Оно не получает private key другого устройства. Это намеренно. Позже можно добавить безопасную регистрацию нового device key / WebAuthn.

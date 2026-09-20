# JEND Core / Guard v2

В v9 браузер больше не загружает собственный `.wasm`-solver. Вся нативная политика JEND Core выполняется **внутри Cloudflare Worker**.

## Поток

1. Браузер один раз создаёт ECDSA P-256 key pair через WebCrypto. Приватный `CryptoKey` создаётся `extractable: false` и сохраняется в IndexedDB.
2. Для `register` или `qr-create` браузер запрашивает одноразовый challenge, передавая только fingerprint публичного ключа Guard.
3. Worker создаёт nonce, TTL, client binding и минимальную задержку. Решение о задержке принимает серверный C-core.
4. Браузер подписывает challenge приватным Guard-ключом.
5. Подпись и публичный Guard-ключ помещаются **внутрь JEND** вместе с основным запросом.
6. Worker расшифровывает JEND, сверяет client binding, TTL, одноразовость и ECDSA-подпись.
7. Серверный C-core считает risk score по серверным признакам. Только после этого выполняется регистрация или создание QR.

## Server-only C core

Исходник:

`native/jend_core.c`

Скомпилированный модуль:

`worker/core/jend-core.wasm`

Он импортируется Worker-кодом через Wrangler как `WebAssembly.Module`. Файл **не находится в `public/` и не копируется в `dist/`**, поэтому сайт не имеет URL, по которому браузер может скачать этот WASM.

Пересобрать локально:

```bash
npm run core:build
```

Для пересборки нужен Clang с target `wasm32`. Обычный Cloudflare deploy компилятор не требует: готовый server-only WASM уже хранится в репозитории.

## Что проверяет Core

Core получает только числовые признаки, сформированные Worker-ом:

- действие (`register` / `qr-create`);
- возраст challenge;
- давление rate-limit;
- известность Guard-устройства;
- same-origin / Origin / `application/jend` флаги;
- предыдущие ошибки Guard.

Криптография остаётся в WebCrypto: ECDSA P-256, SHA-256, HMAC-SHA-256, ECDH, HKDF и AES-GCM.

## Важное ограничение

Это не «невзламываемая CAPTCHA». Любая проверка, полностью выполняемая в браузере, может быть автоматизирована настоящим браузером. Поэтому v9 не пытается спрятать алгоритм в клиенте. Доверие строится на серверных секретах, одноразовых challenge, неподписываемых без Guard private key запросах, JEND, rate limits, replay protection и серверной политике.

Если GitHub-репозиторий публичный, исходник C также публичен через GitHub. Это не должно ломать безопасность: секреты находятся только в Cloudflare. Если вы хотите скрыть реализацию Core дополнительно, репозиторий должен быть private.

# AlfaGen

Сервис для маскирования и восстановления персональных данных. Docker Compose поднимает backend, Redis, Nginx,
веб-панель, генератор нагрузки, Prometheus, Grafana и сбор логов (Loki + Alloy).

## Запуск через Docker

Нужны Git, запущенный Docker с Compose, Bash, Make и OpenSSL.
Go устанавливать не требуется. На Windows используйте WSL2.

```bash
git clone https://github.com/SaveliyDanko/VibeAlfaGen.git
cd VibeAlfaGen
(umask 077; test -f .env || printf 'CONTEXT_ENCRYPTION_KEY=%s\nBENCHMARK_API_KEY=%s\n' \
  "$(openssl rand -base64 32)" "$(openssl rand -hex 32)" > .env)
make admin-up
cat secrets/admin/admin-token
```

Первая сборка требует интернета и занимает несколько минут. Ключи создаются
в `.env` один раз, сертификаты — автоматически. Сохраняйте `.env` и `secrets/`
между запусками.

Порты `8090`, `8443`, `13000` и `9090` должны быть свободны. Если порт занят, перед запуском
добавьте в `.env` `ALFAGEN_ADMIN_PORT=18090` или `ALFAGEN_HTTPS_PORT=18443`.
Для мониторинга доступны `ALFAGEN_GRAFANA_PORT` и `ALFAGEN_PROMETHEUS_PORT`.

## Проверка через веб-панель

1. Откройте **[http://localhost:8090](http://localhost:8090)** и введите токен
   из последней команды. Если меняли порт панели, используйте его в адресе.
2. Во вкладке **«Ручная проверка»** выберите систему `benchmark`, нажмите
   «Новый ID» и введите `Телефон: +7 (999) 123-45-67`.
3. Нажмите **«Маскировать»**, затем **«Восстановить»**: исходный текст должен вернуться.
4. Во вкладке **«Нагрузочный стенд»** выберите `benchmark`, задайте, например,
   100 RPS и длительность `30s`, нажмите «Запустить». После завершения проверьте
   число ошибок, фактический RPS и задержки в отчёте.

## Проверка через curl

Из каталога проекта выполните в Bash (нужен `curl`):

```bash
set -a; . ./.env; set +a
curl -fsS "https://localhost:${ALFAGEN_HTTPS_PORT:-8443}/process" \
  --cacert secrets/mtls/ca.crt \
  --cert secrets/mtls/client.crt --key secrets/mtls/client.key \
  -H 'Content-Type: application/json' \
  -H 'X-System-ID: benchmark' \
  -H "X-API-Key: $BENCHMARK_API_KEY" \
  -d '{"payload":"Телефон: +7 (999) 123-45-67","payload_id":"curl-demo-1"}'
```

Ожидаемый ответ:

```json
{"result":"Телефон: +7 (***) ***-**-67"}
```

Для восстановления повторите команду, заменив `payload` на полученное значение
`result` и сохранив `payload_id`.
Повтор исходного запроса возвращает ту же маску; другой текст с тем же ID даёт
HTTP 409. Для нового примера используйте новый ID.

## Метрики: Grafana и Prometheus

Мониторинг и логи запускаются той же командой `make admin-up`:

- **[Grafana](http://localhost:13000)** — логин `admin`, пароль покажет команда
  `cat secrets/admin/grafana-password`. Откройте **AlfaGen → AlfaGen · Операции**,
  как на VPS: RPS, оценочный TPS, p50, HTTP-коды и найденные ПД.
  В **AlfaGen → AlfaGen Logs** — логи приложения.
- **[Prometheus](http://localhost:9090)** — исходные метрики и запросы PromQL.
  На странице **[Targets](http://localhost:9090/targets)** backend должен быть **UP**.

Запустите нагрузку в админке на `60s` и подождите 30–60 секунд:
метрики собираются каждые 15 секунд. Нажмите обновление дашборда,
чтобы сразу увидеть результат. История Prometheus хранится до суток
или 256 MB, логи — 7 суток; данные сохраняются при остановке.
Интерфейсы мониторинга доступны только с локального компьютера.

## Остановка и повторный запуск

```bash
make admin-down   # остановить, сохранив данные
make admin-up     # снова запустить
make admin-logs   # логи панели и генератора нагрузки
```

## Документация

- [Схема архитектуры и настройки](ARCHITECTURE_AND_CONFIGURATION.md).
- [Производительность и дополнительные возможности](PERFORMANCE_AND_FEATURES.md).
- [Ограничения решения и план развития после хакатона](LIMITATIONS_AND_ROADMAP.md).

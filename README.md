# AWGconfBot

Telegram-бот для управления VPN-клиентами в AmneziaWG v2, установленной и настроеной с помощью AmneziaVPN

Подключается к серверам и управляет Docker-контейнером `amnezia-awg2`.

## Зачем это нужно

AmneziaVPN в магазинах приложений пока не обновилась до поддержки AmneziaWG v2. Чтобы подключиться к серверу с AWG v2, нужно использовать отдельное приложение [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) — оно импортирует `.conf`-файлы напрямую.

Этот бот решает проблему раздачи таких файлов: вместо того чтобы вручную заходить на сервер по SSH, генерировать ключи и собирать конфиги — достаточно написать боту в Telegram, и он сделает всё сам.

По сути это приложение полностью повторяет функционал генерации ключей в AmneziaVPN. 

## Возможности

- Создание и удаление WG-ключей через Telegram
- Поддержка нескольких серверов с переключением между ними
- Разграничение доступа по Telegram UID
- Автоматическое отслеживание изменений конфига без перезапуска
- Работает только в личных сообщениях

## Требования

- Go 1.22+
- Telegram Bot Token (получить у [@BotFather](https://t.me/BotFather))
- Сервер с Docker-контейнером `amnezia-awg2` и SSH-доступом

## Настройка

Скопируйте пример конфига и отредактируйте:

```bash
cp config.yaml.example config.yaml
```

Содержимое `config.yaml`:

```yaml
bot_token: "123456:ABC-token-from-botfather"
servers:
  - name: "Мой сервер"
    ip: "1.2.3.4"
    login: "root"
    pass: "пароль-ssh"
    allowed_uids:
      - 12345678
    last_connected: "2000-01-01T00:00:00Z"
```

- `bot_token` — токен Telegram-бота
- `servers` — список серверов с AmneziaWG
  - `name` — отображаемое имя сервера
  - `ip` — IP-адрес сервера
  - `login` / `pass` — SSH-учётные данные
  - `allowed_uids` — список Telegram UID, которым разрешён доступ к серверу

Узнать свой Telegram UID можно у бота [@userinfobot](https://t.me/userinfobot).

## Команды бота

| Команда         | Описание |
|-----------------|----------|
| `/status`       | Статус текущего сервера и список ключей |
| `/new`     | Создать новый WG-ключ |
| `/delete`  | Удалить ключ по ID |
| `/server` | Переключить активный сервер |

## Сборка и запуск

### Локально

```bash
go build -o awgconfbot .
./awgconfbot
```

Бот ищет `config.yaml` в текущей директории.

### Кросс-компиляция для Linux ARM64

```bash
GOOS=linux GOARCH=arm64 go build -o awgconfbot .
```

### Docker (ARM64)

```bash
make docker-arm64
```

## Запуск на сервере

Не забудьте сначала создать настроить `config.yaml` с настроенным окружением.

### Вариант 1: systemd-сервис

Скопируйте бинарник и конфиг на сервер:

```bash
scp awgconfbot config.yaml root@сервер:/opt/awgconfbot/
```

Создайте файл сервиса `/etc/systemd/system/awgconfbot.service`:

```
touch /etc/systemd/system/awgconfbot.service
vi /etc/systemd/system/awgconfbot.service
```
Впишите туда:

```ini
[Unit]
Description=AWGconfBot Telegram Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/awgconfbot
ExecStart=/opt/awgconfbot/awgconfbot
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Включите (написав :wq) и запустите сервис:

```bash
systemctl daemon-reload
systemctl enable awgconfbot
systemctl start awgconfbot
```

Проверка статуса и логов:

```bash
systemctl status awgconfbot
journalctl -u awgconfbot -f
```

### Вариант 2: Docker

Создайте `docker-compose.yml`:

```yaml
services:
  awgconfbot:
    image: awgconfbot:arm64
    restart: always
    volumes:
      - ./config.yaml:/app/config.yaml
```

Запустите:

```bash
docker compose up -d
```

## Тесты

```bash
go test ./...
go vet ./...
```

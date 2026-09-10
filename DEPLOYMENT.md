# Инструкция по CI/CD, Docker Hub и деплою приложений через GitHub Actions

В проекте настроена автоматизированная система непрерывной интеграции, сборки дистрибутивов и публикации контейнеров через GitHub Actions.

---

## 1. Сборка и публикация Docker-образа (`docker.yml`)

### Что делает workflow:
- **Триггеры**: `git push` в ветку `main`, теги `v*`, а также ручной запуск в интерфейсе GitHub Actions (`workflow_dispatch`).
- Сборка **Multi-Arch** образов (`linux/amd64` и `linux/arm64`).
- Публикация в:
  - **Docker Hub**: `aligorov/ligament_2fa:latest` (и теги версии).
  - **GitHub Container Registry (GHCR)**: `ghcr.io/aligorov/ligament-2fa`.
- Кэширование слоев Docker (`type=gha`) для ускорения сборки.

### Настройка секретов репозитория для Docker Hub:
Перейдите в **Settings → Secrets and variables → Actions** в GitHub репозитории и добавьте:
1. `DOCKERHUB_USERNAME`: ваш логин на Docker Hub (`aligorov`).
2. `DOCKERHUB_TOKEN`: Personal Access Token с Docker Hub (Account Settings → Security → New Access Token).

---

## 2. Сборка клиентских приложений (`build_clients.yml`)

### Поддерживаемые платформы:
- **Windows**: Сборка `.exe` и создание Windows MSI-инсталлятора (`Ligament-2FA-Windows-x64.msi`) с помощью WiX Toolset.
- **Android**: Компиляция релизного `.apk` (`Ligament-2FA.apk`) под ARM64/x86_64.
- **macOS**: Сборка `.app` и создание `.dmg` установщика (`Ligament-2FA-macOS.dmg`) с Drag-and-Drop в `/Applications`.
- **iOS**: Сборка `.ipa` пакета (`Ligament-2FA.ipa`).

### Автоматический релиз на GitHub (GitHub Releases):
При отправке тега версии (например, `v0.4.41`):
```bash
git tag v0.4.41
git push origin v0.4.41
```
GitHub Actions:
1. Параллельно собирает дистрибутивы на виртуальных машинах `windows-latest`, `macos-latest`, `ubuntu-latest`.
2. Скачивает собранные файлы в финальный шаг `create-release`.
3. Рассчитывает контрольные суммы SHA-256 (`SHA256SUMS.txt`).
4. Автоматически публикует **GitHub Release** с прикрепленными готовыми бинарниками для пользователей.

---

## 3. Автоматический деплой на сервер (`deploy.yml`)

После успешной публикации нового Docker-образа запускается workflow деплоя на сервер.

### Секреты для авто-деплоя (опционально):
- `SERVER_HOST`: IP-адрес или домен вашего боевого сервера.
- `SERVER_SSH_KEY`: приватный SSH-ключ для подключения.
- `SERVER_USER`: пользователь SSH (по умолчанию `root`).
- `SERVER_PORT`: SSH порт (по умолчанию `22`).
- `SERVER_DEPLOY_DIR`: директория приложения на сервере (по умолчанию `/opt/twofa`).

### Ручной запуск на сервере (без SSH-ключа):
На любом сервере с установленным Docker достаточно выполнить:
```bash
# 1. Скачать готовый compose файл
curl -fsSL https://raw.githubusercontent.com/aligorov/ligament-2fa/main/docker-compose.client.yml -o docker-compose.yml

# 2. Задать пароль PostgreSQL (обязателен, дефолтного значения нет)
export TWOFA_PG_PASSWORD='свой-пароль-БД'   # или записать в .env рядом с compose

# 3. Запустить контейнеры с загрузкой свежего образа из Docker Hub
docker compose pull
docker compose up -d

# 4. Забрать пароль первичного администратора (в логе он не печатается —
#    только файл admin_password.txt внутри контейнера)
docker cp $(docker compose ps -q twofa):/home/nonroot/admin_password.txt . && cat admin_password.txt
```

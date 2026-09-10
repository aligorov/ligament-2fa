.PHONY: build build-dev test lint docker e2e licgen

# Клиентская сборка: только сервер twofa. Генерация лицензий (cmd/licgen) —
# отдельный вложенный Go-модуль и в ./... / docker-образ НЕ входит.
#
# ADS_CONFIG — вендорское предзаполнение рекламы РСЯ (ключ ads: ID блоков
# и опционально oauth_token статистики), вшивается в бинарник и засевается
# в настройки при первом старте, пока реклама не настраивалась вручную:
#   ADS_CONFIG='{"enabled":true,"blocks":{"login_left":"R-…",…}}' make build
ADS_CONFIG ?= ""
ADSLD := $(if $(ADS_CONFIG),-X main.VendorAdsJSON=$(ADS_CONFIG),)

build:
	go build -ldflags "-X main.BuildDate=$(shell date +%F) $(ADSLD)" -o twofa ./cmd/twofa

# ДЕВ-сборка — ТОЛЬКО ДЛЯ ЛОКАЛЬНЫХ ДЕМО: добавляет в trustedKeys ключ
# dev-1 (лицензии старых демо-файлов). Никогда не поставлять клиентам,
# не собирать в CI и не публиковать (см. internal/license/devkeys_dev.go).
build-dev:
	go build -tags dev -ldflags "-X main.BuildDate=$(shell date +%F) $(ADSLD)" -o twofa ./cmd/twofa

test:
	go test ./...

lint:
	go vet ./...

docker:
	docker build --build-arg BUILD_DATE=$(shell date +%F) 	  --build-arg ADS_CONFIG="$(ADS_CONFIG)" -t twofa:latest .

# E2E-сценарий: testcontainer PostgreSQL + HTTP + RADIUS (нужен Docker).
e2e:
	go test -tags integration ./internal/e2e/ -v -timeout 300s

# Вендорский инструмент выпуска лицензий (отдельный модуль cmd/licgen;
# клиентская сборка его не содержит — см. README «Сборка»).
licgen:
	cd cmd/licgen && go build -o licgen .

# Полный интеграционный прогон: пакеты СЕРИАЛЬНО (-p 1) — миграции разных
# пакетов не гоняются в одну БД параллельно (гонка CREATE TABLE IF NOT EXISTS).
TWOFA_TEST_DSN ?= postgres://twofa:twofa@localhost:55437/twofa?sslmode=disable
test-integration:
	TWOFA_TEST_DSN='$(TWOFA_TEST_DSN)' go test -tags integration -count=1 -p 1 ./...

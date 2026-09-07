# Двухступенчатая сборка: статический бинарник (CGO отключён, миграции
# embedded через migrations/embed.go) → дистролесс без shell и libc.
FROM golang:1.27-alpine AS build
# BUILD_DATE (YYYY-MM-DD) — гейт обновлений лицензии (report §3.4);
# передаётся --build-arg BUILD_DATE=$(date +%F) (Makefile target docker).
ARG BUILD_DATE=""
# ADS_CONFIG — вендорское предзаполнение рекламы РСЯ (ключ ads), см. Makefile.
ARG ADS_CONFIG=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY api ./api
COPY migrations ./migrations
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.BuildDate=${BUILD_DATE} -X main.VendorAdsJSON=${ADS_CONFIG}" -o /twofa ./cmd/twofa

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /twofa /twofa
# HTTP (ACME/Web), HTTP alt, RADIUS auth, RADIUS accounting.
EXPOSE 80/tcp 8080/tcp 1812/udp 1813/udp
ENTRYPOINT ["/twofa"]

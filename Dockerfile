# Двухступенчатая сборка: статический бинарник (CGO отключён, миграции
# embedded через migrations/embed.go) → дистролесс без shell и libc.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /twofa ./cmd/twofa

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /twofa /twofa
# HTTP API/web-UI, RADIUS auth, RADIUS accounting.
EXPOSE 8080/tcp 1812/udp 1813/udp
ENTRYPOINT ["/twofa"]

// Вложенный модуль licgen — генерация лицензий (вендорский инструмент).
// ОН НЕ ВХОДИТ в клиентскую сборку: корневой `go build ./...`, go vet и
// docker-контекст этот каталог не видят (модульная граница Go), а в
// .dockerignore он исключён явно. Сборка — `make licgen` из корня.
module github.com/aligorov/twofa/cmd/licgen

go 1.27.0

require (
	github.com/aligorov/twofa v0.0.0
	github.com/google/uuid v1.6.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/aligorov/twofa => ../..

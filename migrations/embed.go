// Package migrations содержит SQL-миграции, вшитые в бинарник через embed.FS.
// Файлы именуются NNNN_description.sql и применяются в порядке версий NNNN.
package migrations

import "embed"

// FS — встроенные SQL-файлы миграций.
//
//go:embed *.sql
var FS embed.FS

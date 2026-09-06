// Package api встраивает спецификацию OpenAPI (api/openapi.yaml) в бинарник:
// go:embed не может подниматься из internal/api к корню репозитория,
// поэтому файл живёт здесь и переиспользуется HTTP-обработчиками
// internal/api (GET /openapi.yaml и /api/docs).
package api

import _ "embed"

// OpenAPIYAML — байты api/openapi.yaml (OpenAPI 3.0.3, полный JSON REST API
// twofa: /api/v1/auth/*, /api/v1/login*, /api/v1/me/*, /api/v1/admin/*,
// /healthz). Источник истины — файл рядом с этим embed-директивой.
//
//go:embed openapi.yaml
var OpenAPIYAML []byte

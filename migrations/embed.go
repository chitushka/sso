// Package migrations embeds the SQL migrations into the binary so the server
// can apply them itself (SSO_MIGRATE_ON_START) without external tooling.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS

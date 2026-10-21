// Package web holds keelauthd's web page (static files, embedded). The page uses only
// relative addresses, so it works at / on keelAuth itself and under a prefix when keel
// passes it through (docs/02 section 5).
package web

import "embed"

//go:embed static
var Static embed.FS

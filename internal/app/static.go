package app

import "embed"

// staticFS holds the embedded client assets (htmx + CSS) so the binary stays
// self-contained (ADR-0007). Served read-only at /static/.
//
//go:embed static/*
var staticFS embed.FS

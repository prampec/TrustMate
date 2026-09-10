// Package observability provides the cross-cutting logging setup shared by
// every module: structured, JSON-to-stdout by default so downstream
// deployments can wire it into whatever log pipeline they already run
// (ELK, Loki, CloudWatch, ...).
package observability

import (
	"io"
	"log/slog"
)

// NewLogger returns the process-wide structured logger. level follows
// slog's naming (DEBUG, INFO, WARN, ERROR); unrecognized values fall back
// to INFO.
func NewLogger(out io.Writer, level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}

//go:build !debugheaplog

package stacks

import (
	"context"
	"log/slog"
)

const heapAllocDebugging = false

// _logattrs is a helper function that is used by all package loggers and that
// can be switched out with the `debugheaplog` build tag for a non-allocating
// logger that prints out when heap allocations occur.
func _logattrs(l *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	if l != nil {
		l.LogAttrs(context.Background(), level, msg, attrs...)
	}
}

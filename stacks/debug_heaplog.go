//go:build debugheaplog

package stacks

import (
	"log/slog"
	"runtime"
)

const heapAllocDebugging = true

var (
	memstats   runtime.MemStats
	lastAllocs uint64
)

func _logattrs(_ *slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
	runtime.ReadMemStats(&memstats)
	if memstats.TotalAlloc != lastAllocs {
		print("[ALLOC] inc=", int64(memstats.TotalAlloc)-int64(lastAllocs))
		print(" tot=", memstats.TotalAlloc, " seqs")
		println()
	}
	if level == levelTrace {
		print("TRACE ")
	} else if level < slog.LevelDebug {
		print("SEQS ")
	} else {
		print(level.String(), " ")
	}
	print(msg)
	for _, a := range attrs {
		switch a.Value.Kind() {
		case slog.KindString:
			print(" ", a.Key, "=", a.Value.String())
		}
	}
	println()
	runtime.ReadMemStats(&memstats)
	if memstats.TotalAlloc != lastAllocs {
		lastAllocs = memstats.TotalAlloc
	}
}

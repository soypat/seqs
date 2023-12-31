package httpx

import "unsafe"

const (
	argsNoValue  = true
	argsHasValue = false
)

type argsKV struct {
	key     []byte
	value   []byte
	noValue bool
}

func visitArgs(args []argsKV, f func(k, v []byte)) {
	for i, n := 0, len(args); i < n; i++ {
		kv := &args[i]
		f(kv.key, kv.value)
	}
}

func visitArgsKey(args []argsKV, f func(k []byte)) {
	for i, n := 0, len(args); i < n; i++ {
		kv := &args[i]
		f(kv.key)
	}
}

func copyArgs(dst, src []argsKV) []argsKV {
	if cap(dst) < len(src) {
		tmp := make([]argsKV, len(src))
		dstLen := len(dst)
		dst = dst[:cap(dst)] // copy all of dst.
		copy(tmp, dst)
		for i := dstLen; i < len(tmp); i++ {
			// Make sure nothing is nil.
			tmp[i].key = []byte{}
			tmp[i].value = []byte{}
		}
		dst = tmp
	}
	n := len(src)
	dst = dst[:n]
	for i := 0; i < n; i++ {
		dstKV := &dst[i]
		srcKV := &src[i]
		dstKV.key = append(dstKV.key[:0], srcKV.key...)
		if srcKV.noValue {
			dstKV.value = dstKV.value[:0]
		} else {
			dstKV.value = append(dstKV.value[:0], srcKV.value...)
		}
		dstKV.noValue = srcKV.noValue
	}
	return dst
}

func delAllArgs(args []argsKV, key string) []argsKV {
	for i, n := 0, len(args); i < n; i++ {
		kv := &args[i]
		if key == b2s(kv.key) {
			tmp := *kv
			copy(args[i:], args[i+1:])
			n--
			i--
			args[n] = tmp
			args = args[:n]
		}
	}
	return args
}

func setArg(h []argsKV, key, value string, noValue bool) []argsKV {
	n := len(h)
	for i := 0; i < n; i++ {
		kv := &h[i]
		if key == b2s(kv.key) {
			if noValue {
				kv.value = kv.value[:0]
			} else {
				kv.value = append(kv.value[:0], value...)
			}
			kv.noValue = noValue
			return h
		}
	}
	return appendArg(h, key, value, noValue)
}

func appendArg(args []argsKV, key, value string, noValue bool) []argsKV {
	var kv *argsKV
	args, kv = allocArg(args)
	kv.key = append(kv.key[:0], key...)
	if noValue {
		kv.value = kv.value[:0]
	} else {
		kv.value = append(kv.value[:0], value...)
	}
	kv.noValue = noValue
	return args
}

func allocArg(h []argsKV) ([]argsKV, *argsKV) {
	n := len(h)
	if cap(h) > n {
		h = h[:n+1]
	} else {
		h = append(h, argsKV{
			value: []byte{},
		})
	}
	return h, &h[n]
}

func releaseArg(h []argsKV) []argsKV {
	return h[:len(h)-1]
}

func hasArg(h []argsKV, key string) bool {
	for i, n := 0, len(h); i < n; i++ {
		kv := &h[i]
		if key == b2s(kv.key) {
			return true
		}
	}
	return false
}

func peekArgStr(h []argsKV, k string) []byte {
	for i, n := 0, len(h); i < n; i++ {
		kv := &h[i]
		if b2s(kv.key) == k {
			return kv.value
		}
	}
	return nil
}

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// s2b converts string to a byte slice without memory allocation.
func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

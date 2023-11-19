package stack

import (
	"cmp"
	"errors"
	"io"
)

type ring struct {
	buf []byte
	off int
	end int
}

func (r *ring) Write(b []byte) (int, error) {
	free := r.Free()
	if len(b) > free {
		return 0, errors.New("no more space")
	}
	midFree := r.midFree()
	if midFree > 0 {
		n := copy(r.buf[r.end:], b)
		r.end += n
		return n, nil
	}

	n := copy(r.buf[r.end:], b)
	r.end = n
	if n < len(b) {
		n2 := copy(r.buf, b[n:])
		r.end = n2
		n += n2
	}
	return n, nil
}

func (r *ring) Read(b []byte) (int, error) {
	if r.Buffered() == 0 {
		return 0, io.EOF
	}

	if r.end >= r.off {
		// start       off       end      len(buf)
		//   |  sfree   |  used   |  efree   |
		n := copy(b, r.buf[r.off:r.end])
		r.off += n
		r.onReadEnd()
		return n, nil
	}
	// start     end       off     len(buf)
	//   |  used  |  mfree  |  used  |
	n := copy(b, r.buf[r.off:])
	r.off += n
	if n < len(b) {
		n2 := copy(b[n:], r.buf[:r.end])
		r.off = n2
		n += n2
	}
	r.onReadEnd()
	return n, nil
}

func (r *ring) Buffered() int {
	return len(r.buf) - r.Free()
}

func (r *ring) Reset() {
	r.off = 0
	r.end = 0
}

func (r *ring) Free() int {
	if r.end >= r.off {
		// start       off       end      len(buf)
		//   |  sfree   |  used   |  efree   |
		startFree := r.off
		endFree := len(r.buf) - r.end
		return startFree + endFree
	}
	// start     end       off     len(buf)
	//   |  used  |  mfree  |  used  |
	return r.off - r.end
}

func (r *ring) midFree() int {
	if r.end >= r.off {
		return 0
	}
	return r.off - r.end
}

func (r *ring) onReadEnd() {
	if r.off == r.end {
		r.Reset() // We read everything, reset.
	}
}

func max[T cmp.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func min[T cmp.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

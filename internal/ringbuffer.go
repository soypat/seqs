package internal

import (
	"bytes"
	"errors"
	"io"
)

var errRingBufferFull = errors.New("seqs: ringbuffer full")

// Ring is a ring buffer implementation.
type Ring struct {
	Buf []byte
	Off int
	End int
}

func (r *Ring) Write(b []byte) (int, error) {
	free := r.Free()
	if len(b) > free {
		return 0, errRingBufferFull
	}
	midFree := r.midFree()
	if midFree > 0 {
		// start     end       off    len(buf)
		//   |  used  |  mfree  |  used  |
		n := copy(r.Buf[r.End:r.Off], b)
		r.End += n
		return n, nil
	}
	// start       off       end      len(buf)
	//   |  sfree   |  used   |  efree   |
	n := copy(r.Buf[r.End:], b)
	r.End += n
	if n < len(b) {
		n2 := copy(r.Buf, b[n:])
		r.End = n2
		n += n2
	}
	return n, nil
}

func (r *Ring) Read(b []byte) (int, error) {
	if r.Buffered() == 0 {
		return 0, io.EOF
	}

	if r.End > r.Off {
		// start       off       end      len(buf)
		//   |  sfree   |  used   |  efree   |
		n := copy(b, r.Buf[r.Off:r.End])
		r.Off += n
		r.onReadEnd()
		return n, nil
	}
	// start     end       off     len(buf)
	//   |  used  |  mfree  |  used  |
	n := copy(b, r.Buf[r.Off:])
	r.Off += n
	if n < len(b) {
		n2 := copy(b[n:], r.Buf[:r.End])
		r.Off = n2
		n += n2
	}
	r.onReadEnd()
	return n, nil
}

func (r *Ring) Buffered() int {
	return len(r.Buf) - r.Free()
}

func (r *Ring) Reset() {
	r.Off = 0
	r.End = 0
}

func (r *Ring) Free() int {
	if r.Off == 0 {
		return len(r.Buf) - r.End
	}
	if r.Off < r.End {
		// start       off       end      len(buf)
		//   |  sfree   |  used   |  efree   |
		startFree := r.Off
		endFree := len(r.Buf) - r.End
		return startFree + endFree
	}
	// start     end       off     len(buf)
	//   |  used  |  mfree  |  used  |
	return r.Off - r.End
}

func (r *Ring) midFree() int {
	if r.End >= r.Off {
		return 0
	}
	return r.Off - r.End
}

func (r *Ring) onReadEnd() {
	if r.End == len(r.Buf) {
		r.End = 0 // Wrap around.
	}
	if r.Off == len(r.Buf) {
		r.Off = 0 // Wrap around.
	}
	if r.Off == r.End {
		r.Reset() // We read everything, reset.
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *Ring) string() string {
	var b bytes.Buffer
	b.ReadFrom(r)
	return b.String()
}

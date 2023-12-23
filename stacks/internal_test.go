package stacks

import (
	"io"
	"math/rand"
	"testing"
)

func TestRing(t *testing.T) {
	rng := rand.New(rand.NewSource(0))
	const bufSize = 10
	r := &ring{
		buf: make([]byte, bufSize),
	}
	const data = "hello"
	_, err := r.Write([]byte(data))
	if err != nil {
		t.Error(err)
	}
	// Case where data is contiguous and at start of buffer.
	var buf [bufSize]byte
	n, err := fragmentReadInto(r, buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != data {
		t.Fatalf("got %q; want %q", buf[:n], data)
	}

	// Case where data overwrites end of buffer.
	const overdata = "hello world"
	n, err = r.Write([]byte(overdata))
	if err == nil || n > 0 {
		t.Fatal(err, n)
	}

	// Set Random data in ring buffer and read it back.
	for i := 0; i < 32; i++ {
		n := rng.Intn(bufSize)
		copy(buf[:], overdata[:n])
		offset := rng.Intn(bufSize - 1)
		setRingData(r, offset, buf[:n])

		// Case where data wraps around end of buffer.
		n, err = r.Read(buf[:])
		if err != nil {
			break
		}
		if string(buf[:n]) != overdata[:n] {
			t.Error("got", buf[:n], "want", overdata[:n])
		}
	}

	// Set random data and write some more and read it back.
	for i := 0; i < 32; i++ {
		nfirst := rng.Intn(bufSize) / 2
		nsecond := rng.Intn(bufSize) / 2
		if nfirst+nsecond > bufSize {
			nfirst = bufSize - nsecond
		}
		offset := rng.Intn(bufSize - 1)

		copy(buf[:], overdata[:nfirst])
		setRingData(r, offset, buf[:nfirst])
		println(r.end, r.off)
		ngot, err := r.Write([]byte(overdata[nfirst : nfirst+nsecond]))
		if err != nil {
			t.Fatal(err)
		}
		if ngot != nsecond {
			t.Errorf("%d did not write data correctly: got %d; want %d", i, ngot, nsecond)
		}
		buf = [bufSize]byte{}
		// Case where data wraps around end of buffer.
		n, err = r.Read(buf[:])
		if err != nil {
			break
		}
		if n != nfirst+nsecond {
			t.Errorf("got %d; want %d (%d+%d)", n, nfirst+nsecond, nfirst, nsecond)
		}
		if string(buf[:n]) != overdata[:n] {
			t.Errorf("got %q; want %q", buf[:n], overdata[:n])
		}
	}
	_ = r.string()
}

func fragmentReadInto(r io.Reader, buf []byte) (n int, _ error) {
	maxSize := len(buf) / 4
	for {
		ntop := min(n+rand.Intn(maxSize)+1, len(buf))
		ngot, err := r.Read(buf[n:ntop])
		n += ngot
		if err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		if n == len(buf) {
			return n, nil
		}
	}
}

func setRingData(r *ring, offset int, data []byte) {
	if len(data) > len(r.buf) {
		panic("data too large")
	}
	n := copy(r.buf[offset:], data)
	r.end = offset + n
	if n+offset > len(r.buf) {
		// End of buffer not enough to hold data, wrap around.
		n = copy(r.buf, data[n:])
		r.end = n
	}
	r.off = offset
}

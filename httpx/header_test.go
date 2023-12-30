package httpx

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func TestRequestHeaderEmptyValueFromString(t *testing.T) {
	t.Parallel()

	s := "GET / HTTP/1.1\r\n" +
		"EmptyValue1:\r\n" +
		"Host: foobar\r\n" +
		"EmptyValue2: \r\n" +
		"\r\n"
	var h header
	br := bufio.NewReader(bytes.NewBufferString(s))
	if err := h.Read(br); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(h.Host()) != "foobar" {
		t.Fatalf("unexpected host: %q. Expecting %q", h.Host(), "foobar")
	}
	v1 := h.Peek("EmptyValue1")
	if len(v1) > 0 {
		t.Fatalf("expecting empty value. Got %q", v1)
	}
	v2 := h.Peek("EmptyValue2")
	if len(v2) > 0 {
		t.Fatalf("expecting empty value. Got %q", v2)
	}
}

func TestRequestRawHeaders(t *testing.T) {
	t.Parallel()

	kvs := "hOsT: foobar\r\n" +
		"value:  b\r\n" +
		"\r\n"
	t.Run("normalized", func(t *testing.T) {
		s := "GET / HTTP/1.1\r\n" + kvs
		exp := kvs
		var h header
		br := bufio.NewReader(bytes.NewBufferString(s))
		if err := h.Read(br); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(h.Host()) != "foobar" {
			t.Fatalf("unexpected host: %q. Expecting %q", h.Host(), "foobar")
		}
		v2 := h.Peek("Value")
		if !bytes.Equal(v2, []byte{'b'}) {
			t.Fatalf("expecting non empty value. Got %q", v2)
		}
		if raw := h.RawHeaders(); string(raw) != exp {
			t.Fatalf("expected header %q, got %q", exp, raw)
		}
	})
	for _, n := range []int{0, 1, 4, 8} {
		t.Run(fmt.Sprintf("post-%dk", n), func(t *testing.T) {
			l := 1024 * n
			body := make([]byte, l)
			for i := range body {
				body[i] = 'a'
			}
			cl := fmt.Sprintf("Content-Length: %d\r\n", l)
			s := "POST / HTTP/1.1\r\n" + cl + kvs + string(body)
			exp := cl + kvs
			var h header
			br := bufio.NewReader(bytes.NewBufferString(s))
			if err := h.Read(br); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(h.Host()) != "foobar" {
				t.Fatalf("unexpected host: %q. Expecting %q", h.Host(), "foobar")
			}
			v2 := h.Peek("Value")
			if !bytes.Equal(v2, []byte{'b'}) {
				t.Fatalf("expecting non empty value. Got %q", v2)
			}
			if raw := h.RawHeaders(); string(raw) != exp {
				t.Fatalf("expected header %q, got %q", exp, raw)
			}
		})
	}
	t.Run("http10", func(t *testing.T) {
		s := "GET / HTTP/1.0\r\n" + kvs
		exp := kvs
		var h header
		br := bufio.NewReader(bytes.NewBufferString(s))
		if err := h.Read(br); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(h.Host()) != "foobar" {
			t.Fatalf("unexpected host: %q. Expecting %q", h.Host(), "foobar")
		}
		v2 := h.Peek("Value")
		if !bytes.Equal(v2, []byte{'b'}) {
			t.Fatalf("expecting non empty value. Got %q", v2)
		}
		if raw := h.RawHeaders(); string(raw) != exp {
			t.Fatalf("expected header %q, got %q", exp, raw)
		}
	})
	t.Run("no-kvs", func(t *testing.T) {
		s := "GET / HTTP/1.1\r\n\r\n"
		exp := ""
		var h header
		h.DisableNormalizing()
		br := bufio.NewReader(bytes.NewBufferString(s))
		if err := h.Read(br); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(h.Host()) != "" {
			t.Fatalf("unexpected host: %q. Expecting %q", h.Host(), "")
		}
		v1 := h.Peek("NoKey")
		if len(v1) > 0 {
			t.Fatalf("expecting empty value. Got %q", v1)
		}
		if raw := h.RawHeaders(); string(raw) != exp {
			t.Fatalf("expected header %q, got %q", exp, raw)
		}
	})
}

func TestRequestDisableSpecialHeaders(t *testing.T) {
	t.Parallel()

	kvs := "Host: foobar\r\n" +
		"User-Agent: ua\r\n" +
		"Non-Special: val\r\n" +
		"\r\n"

	var h header
	h.DisableSpecialHeader()

	s := "GET / HTTP/1.0\r\n" + kvs
	br := bufio.NewReader(bytes.NewBufferString(s))
	if err := h.Read(br); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// assert order of all headers preserved
	if h.String() != s {
		t.Fatalf("Headers not equal: %q. Expecting %q", h.String(), s)
	}
	// h.SetCanonical([]byte("host"), []byte("notfoobar"))
	// if string(h.Host()) != "foobar" {
	// 	t.Fatalf("unexpected: %q. Expecting %q", h.Host(), "foobar")
	// }
	// if h.String() != "GET / HTTP/1.0\r\nHost: foobar\r\nUser-Agent: ua\r\nNon-Special: val\r\nhost: notfoobar\r\n\r\n" {
	// 	t.Fatalf("custom special header ordering failed: %q", h.String())
	// }
}

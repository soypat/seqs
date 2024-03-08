package httpx

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestResponseHeaderAddContentType(t *testing.T) {
	t.Parallel()

	var h ResponseHeader
	h.Add("Content-Type", "test")

	got := string(h.Peek("Content-Type"))
	expected := "test"
	if got != expected {
		t.Errorf("expected %q got %q", expected, got)
	}

	var buf bytes.Buffer
	if _, err := h.WriteTo(&buf); err != nil {
		t.Fatalf("unexpected error when writing header: %v", err)
	}

	if n := strings.Count(buf.String(), "Content-Type: "); n != 1 {
		t.Errorf("Content-Type occurred %d times", n)
	}
}

func TestRequestHeaderEmptyValueFromString(t *testing.T) {
	t.Parallel()

	s := "GET / HTTP/1.1\r\n" +
		"EmptyValue1:\r\n" +
		"Host: foobar\r\n" +
		"EmptyValue2: \r\n" +
		"\r\n"
	var h RequestHeader
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
		var h RequestHeader
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
		var h RequestHeader
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
		var h RequestHeader
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

	var h RequestHeader
	h.DisableSpecialHeader()

	s := "GET / HTTP/1.0\r\n" + kvs
	br := bufio.NewReader(bytes.NewBufferString(s))
	if err := h.Read(br); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// assert order of all headers preserved
	if h.String() != s {
		t.Fatalf("Headers not equal:\n%q\nExpecting:\n%q\n", h.String(), s)
	}
	// h.SetCanonical([]byte("host"), []byte("notfoobar"))
	// if string(h.Host()) != "foobar" {
	// 	t.Fatalf("unexpected: %q. Expecting %q", h.Host(), "foobar")
	// }
	// if h.String() != "GET / HTTP/1.0\r\nHost: foobar\r\nUser-Agent: ua\r\nNon-Special: val\r\nhost: notfoobar\r\n\r\n" {
	// 	t.Fatalf("custom special header ordering failed: %q", h.String())
	// }
}

func TestRequest(t *testing.T) {
	var req RequestHeader
	req.SetRequestURI("http://example.com")

	var b bytes.Buffer
	b.Write(req.Header())
}

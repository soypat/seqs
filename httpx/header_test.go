package httpx

import (
	"bufio"
	"bytes"
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

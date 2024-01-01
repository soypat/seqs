package dns

import (
	"strings"
	"testing"
)

func TestNameString(t *testing.T) {
	var name Name
	domain := "foo.bar.org"
	domainSplit := strings.Split(domain, ".")
	for i, label := range domainSplit {
		name.AddLabel(label)
		s := name.String()
		if s != strings.Join(domainSplit[:i+1], ".")+"." {
			t.Fatalf("unexpected name string %q", s)
		}
	}
}

func TestNameAppendDecode(t *testing.T) {
	const domain = "foo.bar.org"
	name, err := NewName(domain)
	if err != nil {
		t.Fatal(err)
	} else if name.String() != domain+"." {
		t.Fatalf("unexpected name string %q", name.String())
	}
	var buf [512]byte
	b, err := name.AppendTo(buf[:0])
	if err != nil {
		t.Fatal(err)
	}
	if uint16(len(b)) != name.Len() {
		t.Fatalf("unexpected name length %d", len(b))
	}
	if b[len(b)-1] != 0 {
		t.Fatalf("unexpected name terminator byte after construction: %q", b[len(b)-1])
	}

	var name2 Name
	n, err := name2.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != name.Len() {
		t.Errorf("unexpected name parsed length %q (%d), want %q (%d)", name.data, n, b, name.Len())
	}
	if name2.String() != name.String() {
		t.Errorf("unexpected name string %q, want %q", name2.String(), name.String())
	}

	// Re-decode.
	const okvalidName = "\x03www\x02go\x03dev\x00"
	_, err = name.Decode([]byte(okvalidName))
	if err != nil {
		t.Error("got error decoding valid name", err)
	} else if name.String() != "www.go.dev." {
		t.Error("unexpected name string", name.String())
	}
	b, err = name.AppendTo(buf[:0])
	if err != nil {
		t.Fatal(err)
	}
	if b[len(b)-1] != 0 {
		t.Fatalf("unexpected name terminator byte after decoding: %q", b[len(b)-1])
	}
	if string(b) != okvalidName {
		t.Errorf("unexpected name bytes after decode %q, want %q", b, okvalidName)
	}
	// Decode invalid name.
	const invalidName = "\x03w.w\x02go\x03dev\x00"
	_, err = name.Decode([]byte(invalidName))
	if err == nil {
		t.Error("expected error for invalid name")
	} else if err != errInvalidName {
		t.Errorf("unexpected error %v, want %v", err, errInvalidName)
	}
}

func TestMessageAppendEncode(t *testing.T) {

}

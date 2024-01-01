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

func TestNamePutDecode(t *testing.T) {
	const domain = "foo.bar.org"
	name, err := NewName(domain)
	if err != nil {
		t.Fatal(err)
	} else if name.String() != domain+"." {
		t.Fatalf("unexpected name string %q", name.String())
	}
	var buf [512]byte
	b := name.AppendTo(buf[:0])
	if uint16(len(b)) != name.Len() {
		t.Fatalf("unexpected name length %d", len(b))
	}
	var name2 Name
	n, err := name2.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != name.Len() {
		t.Fatalf("unexpected name parsed length %d, want %d", n, name.Len())
	}
	if name2.String() != name.String() {
		t.Fatalf("unexpected name string %q, want %q", name2.String(), name.String())
	}
}

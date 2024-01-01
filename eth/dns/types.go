package dns

import (
	"strconv"
	"strings"
)

// Types taken from golang.org/x/net/dns/dnsmessage package. See https://pkg.go.dev/golang.org/x/net/dns/dnsmessage.

// Type is a type of DNS request and response.
type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41

	// Question.Type
	TypeWKS   Type = 11
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeAXFR  Type = 252
	TypeALL   Type = 255
)

// A Class is a type of network.
type Class uint16

const (
	// ResourceHeader.Class and Question.Class
	ClassINET   Class = 1
	ClassCSNET  Class = 2
	ClassCHAOS  Class = 3
	ClassHESIOD Class = 4

	// Question.Class
	ClassANY Class = 255
)

// An OpCode is a DNS operation code which specifies the type of query.
type OpCode uint16

const (
	OpCodeQuery        OpCode = 0 // Standard query.
	OpCodeInverseQuery OpCode = 1 // Inverse query.
	OpCodeStatus       OpCode = 2 // Server status request.
)

// An RCode is a DNS response status code.
type RCode uint16

const (
	RCodeSuccess        RCode = 0 // No error condition.
	RCodeFormatError    RCode = 1 // Format error - The name server was unable to interpret the query.
	RCodeServerFailure  RCode = 2 // Server failure - The name server was unable to process this query due to a	problem with the name server.
	RCodeNameError      RCode = 3 // Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the	domain name referenced in the query does not exist.
	RCodeNotImplemented RCode = 4 // Not implemented - The name server does not support the requested kind of query.
	RCodeRefused        RCode = 5 // Refused - The name server refuses to	perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
)

// A ResourceHeader is the header of a DNS resource record. There are
// many types of DNS resource records, but they all share the same header.
type ResourceHeader struct {
	Name   Name
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16
}

// String returns a string representation of the header.
func (h *ResourceHeader) String() string {
	return h.Name.String() + " " + h.Type.String() + " " + h.Class.String() +
		" ttl=" + strconv.FormatUint(uint64(h.TTL), 10) + " len=" + strconv.FormatUint(uint64(h.Length), 10)
}

type Name struct {
	data []byte
}

// NewName parses a domain name and returns a new Name.
func NewName(domain string) (*Name, error) {
	var name Name
	for len(domain) > 0 {
		idx := strings.IndexByte(domain, '.')
		done := idx < 0 || idx+1 > len(domain)
		if done {
			idx = len(domain)
		}
		if !name.CanAddLabel(domain[:idx]) {
			return nil, errCantAddLabel
		}
		name.AddLabel(domain[:idx])
		if done {
			break
		}
		domain = domain[idx+1:]
	}
	return &name, nil
}

type Question struct {
	Name  Name
	Type  Type
	Class Class
}

// Len returns the length over-the-wire of the encoded Name.
func (n *Name) Len() uint16 {
	return uint16(len(n.data))
}

func (n *Name) AppendTo(b []byte) []byte {
	return append(b, n.data...)
}

func (n *Name) String() string {
	b := make([]byte, 0, len(n.data)+3)
	return string(n.AppendDottedTo(b))
}

func (n *Name) AppendDottedTo(b []byte) []byte {
	n.VisitLabels(func(label []byte) {
		b = append(b, label...)
		b = append(b, '.')
	})
	return b
}

// Decode resets internal Name buffer and reads raw wire data from buffer, returning any error encountered.
func (n *Name) Decode(b []byte) (uint16, error) {
	n.Reset()
	return visitAllLabels(b, 0, n.vistAddLabel)
}

// Reset resets the Name labels to be empty and reuses buffer.
func (n *Name) Reset() { n.data = n.data[:0] }

// CanAddLabel reports whether the label can be added to the name.
func (n *Name) CanAddLabel(label string) bool {
	return len(label) != 0 && len(label) <= 63 && len(label)+len(n.data)+2 <= 255 && // Include len+terminator+label.
		label[len(label)-1] != 0 && // We do not support implicitly zero-terminated labels.
		strings.IndexByte(label, '.') < 0 // See issue golang/go#56246
}

// AddLabel adds a label to the name. If n.CanAddLabel(label) returns false, it panics.
func (n *Name) AddLabel(label string) {
	if !n.CanAddLabel(label) {
		panic(errCantAddLabel.Error())
	}
	if n.isTerminated() {
		n.data = n.data[:len(n.data)-1] // Remove terminator if present to add another label.
	}
	n.data = append(n.data, byte(len(label)))
	n.data = append(n.data, label...)
	n.data = append(n.data, 0)
}

func (n *Name) vistAddLabel(label []byte) {
	n.data = append(n.data, byte(len(label)))
	n.data = append(n.data, label...)
}

func (n *Name) isTerminated() bool {
	return len(n.data) > 0 && n.data[len(n.data)-1] == 0
}

func (n *Name) VisitLabels(fn func(label []byte)) error {
	if len(n.data) > 255 {
		return errNameTooLong
	}
	_, err := visitAllLabels(n.data, 0, fn)
	return err
}

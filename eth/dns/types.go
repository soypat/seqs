package dns

import (
	"encoding/binary"
	"math"
	"slices"
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

type Message struct {
	Header
	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

type Question struct {
	Name  Name
	Type  Type
	Class Class
}

type Resource struct {
	Header ResourceHeader
	data   []byte
}

// A ResourceHeader is the header of a DNS resource record. There are
// many types of DNS resource records, but they all share the same header.
type ResourceHeader struct {
	Name   Name
	Type   Type
	Class  Class
	TTL    uint32
	Length uint16
}

type Name struct {
	data []byte
}

func (m *Message) Decode(msg []byte) (uint16, error) {
	if len(msg) < SizeHeader {
		return 0, errBaseLen
	} else if len(msg) > math.MaxUint16 {
		return 0, errResTooLong
	}
	m.Reset()
	m.Header = DecodeHeader(msg)
	off := uint16(SizeHeader)
	switch {
	case m.Header.QDCount > uint16(cap(m.Questions)):
		return off, errTooManyQuestions
	case m.Header.ANCount > uint16(cap(m.Answers)):
		return off, errTooManyAnswers
	case m.Header.NSCount > uint16(cap(m.Authorities)):
		return off, errTooManyAuthorities
	case m.Header.ARCount > uint16(cap(m.Additionals)):
		return off, errTooManyAdditionals
	}

	m.Questions = m.Questions[:m.QDCount]
	for i := uint16(0); i < m.QDCount; i++ {
		decoded, err := m.Questions[i].Decode(msg[off:])
		off += decoded
		if err != nil {
			m.Questions = m.Questions[:i] // Trim non-decoded/failed questions.
			return off, err
		}

	}

	off, err := decodeToCapResources(&m.Answers, msg, m.ANCount, off)
	if err != nil {
		return off, err
	}
	off, err = decodeToCapResources(&m.Answers, msg, m.ANCount, off)
	if err != nil {
		return off, err
	}
	off, err = decodeToCapResources(&m.Authorities, msg, m.NSCount, off)
	if err != nil {
		return off, err
	}
	off, err = decodeToCapResources(&m.Additionals, msg, m.ARCount, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func decodeToCapResources(dst *[]Resource, msg []byte, nrec, off uint16) (uint16, error) {
	*dst = (*dst)[:nrec]
	for i := uint16(0); i < nrec; i++ {
		decoded, err := (*dst)[i].Decode(msg[off:])
		off += decoded
		if err != nil {
			*dst = (*dst)[:i] // Trim non-decoded/failed resources.
			return off, err
		}
	}
	return off, nil
}

func (m *Message) AppendTo(buf []byte) (_ []byte, err error) {
	buf = slices.Grow(buf, int(m.Len()))
	m.Header.Put(buf[len(buf) : len(buf)+SizeHeader])
	buf = buf[:len(buf)+SizeHeader]
	for _, q := range m.Questions {
		buf, err = q.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	for _, r := range m.Answers {
		buf, err = r.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	for _, r := range m.Authorities {
		buf, err = r.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	for _, r := range m.Additionals {
		buf, err = r.appendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

func (m *Message) Len() uint16 {
	return SizeHeader + m.lenResources()
}

func (m *Message) lenResources() (l uint16) {
	for i := range m.Questions {
		l += m.Questions[i].Len()
	}
	for i := range m.Answers {
		l += m.Answers[i].Len()
	}
	for i := range m.Authorities {
		l += m.Authorities[i].Len()
	}
	for i := range m.Additionals {
		l += m.Additionals[i].Len()
	}
	return l
}

func (m *Message) SetMaxResources(maxQ, maxAns, maxAuth, maxAdd uint16) {
	m.Questions = slices.Grow(m.Questions, int(maxQ))
	m.Answers = slices.Grow(m.Answers, int(maxQ))
	m.Authorities = slices.Grow(m.Authorities, int(maxQ))
	m.Additionals = slices.Grow(m.Additionals, int(maxQ))
}

func (m *Message) Reset() {
	m.Header = Header{}
	m.Questions = m.Questions[:0]
	m.Answers = m.Answers[:0]
	m.Authorities = m.Authorities[:0]
	m.Additionals = m.Additionals[:0]
}

// String returns a string representation of the header.
func (h *ResourceHeader) String() string {
	return h.Name.String() + " " + h.Type.String() + " " + h.Class.String() +
		" ttl=" + strconv.FormatUint(uint64(h.TTL), 10) + " len=" + strconv.FormatUint(uint64(h.Length), 10)
}

func (r *Resource) Reset() {
	r.Header.Reset()
	r.data = r.data[:0]
}

func (r *Resource) Len() uint16 {
	return r.Header.Name.Len() + 10 + uint16(len(r.data))
}

func (q *Question) Reset() {
	q.Name.Reset()
	*q = Question{Name: q.Name} // Reuse Name's buffer.
}

// Len returns Question's length over-the-wire.
func (q *Question) Len() uint16 { return q.Name.Len() + 4 }

func (r *ResourceHeader) Reset() {
	r.Name.Reset()
	*r = ResourceHeader{Name: r.Name} // Reuse Name's buffer.
}

func (q *Question) Decode(b []byte) (uint16, error) {
	off, err := q.Name.Decode(b)
	if err != nil {
		return off, err
	}
	if off+4 > uint16(len(b)) {
		return off, errResourceLen
	}
	q.Type = Type(binary.BigEndian.Uint16(b[off:]))
	q.Class = Class(binary.BigEndian.Uint16(b[off+2:]))
	return off + 4, nil
}

func (q *Question) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = q.Name.AppendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append16(buf, uint16(q.Type))
	buf = append16(buf, uint16(q.Class))
	return buf, nil
}

// String returns a string representation of the Question with the Name in dotted format.
func (q *Question) String() string {
	return q.Name.String() + " " + q.Type.String() + " " + q.Class.String()
}

func (r *Resource) Decode(b []byte) (uint16, error) {
	off, err := r.Header.Decode(b)
	if err != nil {
		return off, err
	}
	if off+r.Header.Length > uint16(len(b)) {
		return off, errResourceLen
	}
	r.data = append(r.data, b[off:off+uint16(r.Header.Length)]...)
	return off + uint16(r.Header.Length), nil
}

func (r *Resource) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = r.Header.appendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append(buf, r.data...)
	return buf, nil
}

func (rhdr *ResourceHeader) Decode(b []byte) (uint16, error) {
	off, err := rhdr.Name.Decode(b)
	if err != nil {
		return off, err
	}
	if off+10 > uint16(len(b)) {
		return off, errResourceLen
	}
	rhdr.Type = Type(binary.BigEndian.Uint16(b[off:]))     // 2
	rhdr.Class = Class(binary.BigEndian.Uint16(b[off+2:])) // 4
	rhdr.TTL = binary.BigEndian.Uint32(b[off+4:])          // 8
	rhdr.Length = binary.BigEndian.Uint16(b[off+8:])       // 10
	return off + 10, nil
}

func (rhdr *ResourceHeader) appendTo(buf []byte) (_ []byte, err error) {
	buf, err = rhdr.Name.AppendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append16(buf, uint16(rhdr.Type))
	buf = append16(buf, uint16(rhdr.Class))
	buf = append32(buf, rhdr.TTL)
	buf = append16(buf, rhdr.Length)
	return buf, nil
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

// Len returns the length over-the-wire of the encoded Name.
func (n *Name) Len() uint16 {
	return uint16(len(n.data))
}

// AppendTo appends the Name to b in wire format and returns the resulting slice.
func (n *Name) AppendTo(b []byte) ([]byte, error) {
	if len(n.data) == 0 {
		return b, errInvalidName
	}
	return append(b, n.data...), nil
}

// String returns a string representation of the name in dotted format.
func (n *Name) String() string {
	b := make([]byte, 0, len(n.data)+3)
	return string(n.AppendDottedTo(b))
}

// AppendDottedTo appends the Name to b in dotted format and returns the resulting slice.
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
	off, err := visitAllLabels(b, 0, n.vistAddLabel)
	if err != nil {
		n.Reset()
		return off, err
	}
	n.data = append(n.data, 0) // Add terminator, off counts the terminator already in visitAllLabels.
	return off, nil
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

func append16(b []byte, v uint16) []byte {
	binary.BigEndian.PutUint16(b[len(b):len(b)+2], v)
	return b[:len(b)+2]
}

func append32(b []byte, v uint32) []byte {
	binary.BigEndian.PutUint32(b[len(b):len(b)+4], v)
	return b[:len(b)+4]
}

package dns

import (
	"encoding/binary"
	"math"
	"slices"
	"strconv"
	"strings"
)

const allowCompression = true

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

//go:generate stringer -type=RCode -trimprefix=RCode -output=rcode_string.go
const (
	RCodeSuccess        RCode = 0 // No error condition.
	RCodeFormatError    RCode = 1 // Format error - The name server was unable to interpret the query.
	RCodeServerFailure  RCode = 2 // Server failure - The name server was unable to process this query due to a	problem with the name server.
	RCodeNameError      RCode = 3 // Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the	domain name referenced in the query does not exist.
	RCodeNotImplemented RCode = 4 // Not implemented - The name server does not support the requested kind of query.
	RCodeRefused        RCode = 5 // Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
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

// Decode decodes the DNS message in b into m. It returns the number of bytes
// consumed from b (0 if no bytes were consumed) and any error encountered.
// If the message was not completely parsed due to LimitResourceDecoding,
// incompleteButOK is true and an error is returned, though the message is still usable.
func (m *Message) Decode(msg []byte) (_ uint16, incompleteButOK bool, err error) {
	if len(msg) < SizeHeader {
		return 0, false, errBaseLen
	} else if len(msg) > math.MaxUint16 {
		return 0, false, errResTooLong
	}
	m.Reset()
	m.Header = DecodeHeader(msg)
	off := uint16(SizeHeader)
	// Return tooManyErr if found to flag to the caller that the message was
	// decoded but contained too many resources to decode completely.
	var tooManyErr error
	switch {
	case m.Header.QDCount > uint16(cap(m.Questions)):
		tooManyErr = errTooManyQuestions
	case m.Header.ANCount > uint16(cap(m.Answers)):
		tooManyErr = errTooManyAnswers
	case m.Header.NSCount > uint16(cap(m.Authorities)):
		tooManyErr = errTooManyAuthorities
	case m.Header.ARCount > uint16(cap(m.Additionals)):
		tooManyErr = errTooManyAdditionals
	}
	nq := m.QDCount
	if nq > uint16(cap(m.Questions)) {
		nq = uint16(cap(m.Questions))
	}
	m.Questions = m.Questions[:nq]
	for i := uint16(0); i < nq; i++ {
		off, err = m.Questions[i].Decode(msg, off)
		if err != nil {
			m.Questions = m.Questions[:i] // Trim non-decoded/failed questions.
			return off, false, err
		}
	}
	// Skip undecoded questions.
	for i := uint16(0); i < m.QDCount-nq; i++ {
		off, err = skipQuestion(msg, off)
		if err != nil {
			return off, false, err
		}
	}

	off, err = decodeToCapResources(&m.Answers, msg, m.ANCount, off)
	if err != nil {
		return off, false, err
	}
	off, err = decodeToCapResources(&m.Authorities, msg, m.NSCount, off)
	if err != nil {
		return off, false, err
	}
	off, err = decodeToCapResources(&m.Additionals, msg, m.ARCount, off)
	if err != nil {
		return off, false, err
	}
	return off, tooManyErr != nil, tooManyErr
}

func decodeToCapResources(dst *[]Resource, msg []byte, nrec, off uint16) (_ uint16, err error) {
	originalRec := nrec
	if nrec > uint16(cap(*dst)) {
		nrec = uint16(cap(*dst)) // Decode up to cap. Caller will return an error flag.
	}
	*dst = (*dst)[:nrec]
	for i := uint16(0); i < nrec; i++ {
		off, err = (*dst)[i].Decode(msg, off)
		if err != nil {
			*dst = (*dst)[:i] // Trim non-decoded/failed resources.
			return off, err
		}
	}
	// Parse undecoded resources, effectively skipping them.
	for i := uint16(0); i < originalRec-nrec; i++ {
		off, err = skipResource(msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func skipQuestion(msg []byte, off uint16) (_ uint16, err error) {
	off, err = skipName(msg, off)
	if err != nil {
		return off, err
	}
	if off+4 > uint16(len(msg)) {
		return off, errBaseLen
	}
	return off + 4, nil
}

func skipResource(msg []byte, off uint16) (_ uint16, err error) {
	off, err = skipName(msg, off)
	if err != nil {
		return off, err
	}
	// | Name... | Type16 | Class16 | TTL32 | Length16 | Data... |
	datalen := binary.BigEndian.Uint16(msg[off+8:])
	off += datalen + 10
	if off > uint16(len(msg)) {
		return off, errBaseLen
	}
	return off, nil
}

func skipName(msg []byte, off uint16) (uint16, error) {
	return visitAllLabels(msg, off, func(b []byte) {}, allowCompression)
}

func (m *Message) AppendTo(buf []byte) (_ []byte, err error) {
	m.QDCount = uint16(len(m.Questions))
	m.ANCount = uint16(len(m.Answers))
	m.NSCount = uint16(len(m.Authorities))
	m.ARCount = uint16(len(m.Additionals))

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

func (m *Message) AddQuestions(questions []Question) {
	// This question slice handling here is done in spirit of DNSClient being owner of its own buffer.
	// If this is not done we risk the Questions being edited by user and interfering with the DNS request.
	qoff := len(m.Questions)
	m.Questions = slices.Grow(m.Questions, len(questions))
	m.Questions = m.Questions[:qoff+len(questions)]
	for i := range questions {
		m.Questions[qoff+i].Name.CloneFrom(questions[i].Name)
		m.Questions[qoff+i].Type = questions[i].Type
		m.Questions[qoff+i].Class = questions[i].Class
	}
}

func (m *Message) LimitResourceDecoding(maxQ, maxAns, maxAuth, maxAdd uint16) {
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

func (r *Resource) RawData() []byte {
	length := r.Header.Length
	if int(length) > len(r.data) {
		length = uint16(len(r.data))
	}
	return r.data[:length]
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

func (q *Question) Decode(msg []byte, off uint16) (uint16, error) {
	off, err := q.Name.Decode(msg, off)
	if err != nil {
		return off, err
	}
	if off+4 > uint16(len(msg)) {
		return off, errResourceLen
	}
	q.Type = Type(binary.BigEndian.Uint16(msg[off:]))
	q.Class = Class(binary.BigEndian.Uint16(msg[off+2:]))
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

func (r *Resource) Decode(b []byte, off uint16) (uint16, error) {
	off, err := r.Header.Decode(b, off)
	if err != nil {
		return off, err
	}
	if r.Header.Length > uint16(len(b[off:])) {
		return off, errResourceLen
	}
	r.data = append(r.data[:0], b[off:off+r.Header.Length]...)
	return off + r.Header.Length, nil
}

func (r *Resource) appendTo(buf []byte) (_ []byte, err error) {
	r.Header.Length = uint16(len(r.data))
	buf, err = r.Header.appendTo(buf)
	if err != nil {
		return buf, err
	}
	buf = append(buf, r.data...)
	return buf, nil
}

func (rhdr *ResourceHeader) Decode(msg []byte, off uint16) (uint16, error) {
	off, err := rhdr.Name.Decode(msg, off)
	if err != nil {
		return off, err
	}
	if off+10 > uint16(len(msg)) {
		return off, errResourceLen
	}
	rhdr.Type = Type(binary.BigEndian.Uint16(msg[off:]))     // 2
	rhdr.Class = Class(binary.BigEndian.Uint16(msg[off+2:])) // 4
	rhdr.TTL = binary.BigEndian.Uint32(msg[off+4:])          // 8
	rhdr.Length = binary.BigEndian.Uint16(msg[off+8:])       // 10
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

func MustNewName(s string) Name {
	name, err := NewName(s)
	if err != nil {
		panic(err)
	}
	return name
}

// NewName parses a domain name and returns a new Name.
func NewName(domain string) (Name, error) {
	if len(domain) == 1 && domain[0] == '.' {
		return Name{data: []byte{0}}, nil
	}
	var name Name
	for len(domain) > 0 {
		idx := strings.IndexByte(domain, '.')
		done := idx < 0 || idx+1 > len(domain)
		if done {
			idx = len(domain)
		}
		if !name.CanAddLabel(domain[:idx]) {
			return Name{}, errCantAddLabel
		}
		name.AddLabel(domain[:idx])
		if done {
			break
		}
		domain = domain[idx+1:]
	}
	return name, nil
}

// Len returns the length over-the-wire of the encoded Name.
func (n *Name) Len() uint16 {
	return uint16(len(n.data))
}

func (n *Name) CloneFrom(ex Name) {
	n.data = append(n.data[:0], ex.data...)
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
func (n *Name) Decode(b []byte, off uint16) (uint16, error) {
	n.Reset()
	off, err := visitAllLabels(b, off, n.vistAddLabel, allowCompression)
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
	_, err := visitAllLabels(n.data, 0, fn, allowCompression)
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

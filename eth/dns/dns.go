package dns

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"unsafe"
)

// common errors. Taken from golang.org/x/net/dns/dnsmessage module.
var (
	errNameTooLong        = errors.New("DNS name exceeds maximum length")
	errNoNullTerm         = errors.New("DNS name missing null terminator")
	errCalcLen            = errors.New("DNS calculated name label length exceeds remaining buffer length")
	errCantAddLabel       = errors.New("long/empty/zterm/escape DNS label or not enough space")
	errBaseLen            = errors.New("insufficient data for base length type")
	errReserved           = errors.New("segment prefix is reserved")
	errTooManyPtr         = errors.New("too many pointers (>10)")
	errInvalidPtr         = errors.New("invalid pointer")
	errInvalidName        = errors.New("invalid dns name")
	errNilResouceBody     = errors.New("nil resource body")
	errResourceLen        = errors.New("insufficient data for resource body length")
	errSegTooLong         = errors.New("segment length too long")
	errZeroSegLen         = errors.New("zero length segment")
	errResTooLong         = errors.New("resource length too long")
	errTooManyQuestions   = errors.New("too many Questions")
	errTooManyAnswers     = errors.New("too many Answers")
	errTooManyAuthorities = errors.New("too many Authorities")
	errTooManyAdditionals = errors.New("too many Additionals")
	errNonCanonicalName   = errors.New("name is not in canonical format (it must end with a .)")
	errStringTooLong      = errors.New("character string exceeds maximum length (255)")
	errCompressedSRV      = errors.New("compressed name in SRV resource data")
)

// Global parameters.
const (
	// SizeHeader is the length (in bytes) of a DNS header.
	// A header is comprised of 6 uint16s and no padding.
	SizeHeader = 6 * 2
	// The Internet supports name server access using TCP [RFC-793] on server
	// port 53 (decimal) as well as datagram access using UDP [RFC-768] on UDP port 53 (decimal).
	ServerPort = 53
	ClientPort = 53
	// Messages carried by UDP are restricted to 512 bytes (not counting the IP
	// or UDP headers).  Longer messages are truncated and the TC bit is set in the header.
	MaxSizeUDP = 512
)

type Header struct {
	// Generated for any kind of query.  This identifier is copied
	// the corresponding reply and can be used by the requester to
	// match up replies to outstanding queries.
	TransactionID uint16      // 0:2
	Flags         HeaderFlags // 2:4
	// number of entries in the question section.
	QDCount uint16 // 4:6
	// number of resource records in the answer section.
	ANCount uint16 // 6:8
	// number of name server resource records in the authority records section.
	NSCount uint16 // 8:10
	// number of resource records in the additional records section.
	ARCount uint16 // 10:12
}

// HeaderFlags gathers the flags in bits 16..31 of the header.
type HeaderFlags uint16

func (dhdr *Header) Put(b []byte) {
	_ = b[SizeHeader-1] // bounds check hint to compiler; see golang.org/issue/14808
	binary.BigEndian.PutUint16(b[0:2], dhdr.TransactionID)
	binary.BigEndian.PutUint16(b[2:4], uint16(dhdr.Flags))
	binary.BigEndian.PutUint16(b[4:6], dhdr.QDCount)
	binary.BigEndian.PutUint16(b[6:8], dhdr.ANCount)
	binary.BigEndian.PutUint16(b[8:10], dhdr.NSCount)
	binary.BigEndian.PutUint16(b[10:12], dhdr.ARCount)
}

func DecodeHeader(b []byte) (dhdr Header) {
	_ = b[SizeHeader-1] // bounds check hint to compiler; see golang.org/issue/14808
	dhdr.TransactionID = binary.BigEndian.Uint16(b[0:2])
	dhdr.Flags = HeaderFlags(binary.BigEndian.Uint16(b[2:4]))
	dhdr.QDCount = binary.BigEndian.Uint16(b[4:6])
	dhdr.ANCount = binary.BigEndian.Uint16(b[6:8])
	dhdr.NSCount = binary.BigEndian.Uint16(b[8:10])
	dhdr.ARCount = binary.BigEndian.Uint16(b[10:12])
	return dhdr
}

// NewClientHeaderFlags creates the header flags for a client request.
func NewClientHeaderFlags(op OpCode, enableRecursion bool) HeaderFlags {
	return HeaderFlags(op&0b1111)<<11 | HeaderFlags(b2u8(enableRecursion))<<7
}

// IsResponse returns QR bit which specifies whether this message is a query (0), or a response (1).
func (flags HeaderFlags) IsResponse() bool { return flags&(1<<15) != 0 }

// OpCode returns the 4-bit opcode.
func (flags HeaderFlags) OpCode() OpCode { return OpCode(flags>>11) & 0b1111 }

// IsAuthorativeAnswer returns AA bit which specifies that the responding name server is an authority for the domain name in question section.
func (flags HeaderFlags) IsAuthorativeAnswer() bool { return flags&(1<<10) != 0 }

// IsTruncated returns TC bit which specifies that this message was truncated due to length greater than that permitted on the transmission channel.
func (flags HeaderFlags) IsTruncated() bool { return flags&(1<<9) != 0 }

// IsRecursionDesired returns RD bit which specifies whether recursive query support is desired by the client. Is optionally set by client.
func (flags HeaderFlags) IsRecursionDesired() bool { return flags&(1<<8) != 0 }

// IsRecursionAvailable returns RA bit which specifies whether recursive query support is available by the server.
func (flags HeaderFlags) IsRecursionAvailable() bool { return flags&(1<<7) != 0 }

// ResponseCode returns the 4-bit response code set as part of responses.
func (flags HeaderFlags) ResponseCode() RCode { return RCode(flags & 0b1111) }

func (flags HeaderFlags) String() string {
	buf := make([]byte, 0, 16)
	return string(flags.appendF(buf))
}

func (flags HeaderFlags) appendF(buf []byte) []byte {
	writeBit := func(b bool, s string) {
		if b {
			buf = append(buf, s...)
			buf = append(buf, ' ')
		}
	}
	writeBit(flags.IsResponse(), "QR")
	writeBit(flags.IsAuthorativeAnswer(), "AA")
	writeBit(flags.IsTruncated(), "TC")
	writeBit(flags.IsRecursionDesired(), "RD")
	writeBit(flags.IsRecursionAvailable(), "RA")
	buf = append(buf, flags.OpCode().String()...)
	buf = append(buf, ' ')
	buf = append(buf, flags.ResponseCode().String()...)
	return buf
}

func visitAllLabels(msg []byte, off uint16, fn func(b []byte), allowCompression bool) (uint16, error) {
	// currOff is the current working offset.
	currOff := off
	if len(msg) > math.MaxUint16 {
		return off, errResTooLong
	}
	// ptr is the number of pointers followed.
	var ptr uint8
	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	var newOff = off

LOOP:
	for {
		if currOff >= uint16(len(msg)) {
			return off, errBaseLen
		}
		c := uint16(msg[currOff])
		currOff++
		switch c & 0xc0 {
		case 0x00: // String label (segment).
			if c == 0x00 {
				break LOOP // Nominal end of name, always ends with null terminator.
			}
			endOff := currOff + c
			if endOff > uint16(len(msg)) {
				return off, errCalcLen
			}

			// Reject names containing dots. See issue golang/go#56246
			if strings.IndexByte(b2s(msg[currOff:endOff]), '.') >= 0 {
				return off, errInvalidName
			}

			fn(msg[currOff:endOff])
			currOff = endOff

		case 0xc0: // Pointer.
			// https://cs.opensource.google/go/x/net/+/refs/tags/v0.19.0:dns/dnsmessage/message.go;l=2078
			if !allowCompression {
				return off, errCompressedSRV
			}
			if currOff >= uint16(len(msg)) {
				return off, errInvalidPtr
			}
			c1 := msg[currOff]
			currOff++
			if ptr == 0 {
				newOff = currOff
			}
			// Don't follow too many pointers, maybe there's a loop.
			if ptr++; ptr > 10 {
				return off, errTooManyPtr
			}
			currOff = (c^0xC0)<<8 | uint16(c1)
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return off, errReserved
		}
	}
	if ptr == 0 {
		newOff = currOff
	}
	return newOff, nil
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func b2s(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

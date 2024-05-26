package seqs

import (
	"math/bits"
	"strconv"
	"unsafe"
)

// Segment represents an incoming/outgoing TCP segment in the sequence space.
type Segment struct {
	SEQ     Value // sequence number of first octet of segment. If SYN is set it is the initial sequence number (ISN) and the first data octet is ISN+1.
	ACK     Value // acknowledgment number. If ACK is set it is sequence number of first octet the sender of the segment is expecting to receive next.
	DATALEN Size  // The number of octets occupied by the data (payload) not counting SYN and FIN.
	WND     Size  // segment window
	Flags   Flags // TCP flags.
}

// LEN returns the length of the segment in octets including SYN and FIN flags.
func (seg *Segment) LEN() Size {
	add := Size(seg.Flags>>0) & 1 // Add FIN bit.
	add += Size(seg.Flags>>1) & 1 // Add SYN bit.
	return seg.DATALEN + add
}

// End returns the sequence number of the last octet of the segment.
func (seg *Segment) Last() Value {
	seglen := seg.LEN()
	if seglen == 0 {
		return seg.SEQ
	}
	return Add(seg.SEQ, seglen) - 1
}

// StringExchange returns a string representation of a segment exchange over
// a network in RFC9293 styled visualization. invertDir inverts the arrow directions.
// i.e:
//
//	SynSent --> <SEQ=300><ACK=91>[SYN,ACK]  --> SynRcvd
func StringExchange(seg Segment, A, B State, invertDir bool) string {
	b := make([]byte, 0, 64)
	b = appendStringExchange(b, seg, A, B, invertDir)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// appendStringExchange appends a RFC9293 styled visualization of exchange to buf.
// i.e:
//
//	SynSent --> <SEQ=300><ACK=91>[SYN,ACK]  --> SynRcvd
func appendStringExchange(buf []byte, seg Segment, A, B State, invertDir bool) []byte {
	const emptySpaces = "            "
	appendVal := func(buf []byte, name string, i Value) []byte {
		buf = append(buf, '<')
		buf = append(buf, name...)
		buf = append(buf, '=')
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, '>')
		return buf
	}
	startLen := len(buf)
	dirSep := []byte(" --> ")
	if invertDir {
		dirSep = []byte(" <-- ")
	}
	astr := A.String()
	buf = append(buf, astr...)
	if len(astr) < 11 {
		buf = append(buf, emptySpaces[:11-len(astr)]...) // Fill up to 11 characters
	}
	buf = append(buf, dirSep...)
	buf = appendVal(buf, "SEQ", seg.SEQ)
	buf = appendVal(buf, "ACK", seg.ACK)
	if seg.DATALEN > 0 {
		buf = appendVal(buf, "DATA", Value(seg.DATALEN))
	}
	buf = append(buf, '[')
	buf = seg.Flags.AppendFormat(buf)
	buf = append(buf, ']')
	if len(buf)-startLen < 44 {
		buf = append(buf, emptySpaces[:44-len(buf)]...) // Fill up to 44 characters
	}
	buf = append(buf, dirSep...)
	buf = append(buf, B.String()...)
	return buf
}

// Flags is a TCP flags masked implementation i.e: SYN, FIN, ACK.
type Flags uint16

const (
	FlagFIN Flags = 1 << iota // FlagFIN - No more data from sender.
	FlagSYN                   // FlagSYN - Synchronize sequence numbers.
	FlagRST                   // FlagRST - Reset the connection.
	FlagPSH                   // FlagPSH - Push function.
	FlagACK                   // FlagACK - Acknowledgment field significant.
	FlagURG                   // FlagURG - Urgent pointer field significant.
	FlagECE                   // FlagECE - ECN-Echo has a nonce-sum in the SYN/ACK.
	FlagCWR                   // FlagCWR - Congestion Window Reduced.
	FlagNS                    // FlagNS  - Nonce Sum flag (see RFC 3540).
)

// The union of SYN|FIN|PSH and ACK flags is commonly found throughout the specification, so we define unexported shorthands.
const (
	synack = FlagSYN | FlagACK
	finack = FlagFIN | FlagACK
	pshack = FlagPSH | FlagACK
)

// HasAll checks if mask bits are all set in the receiver flags.
func (flags Flags) HasAll(mask Flags) bool { return flags&mask == mask }

// HasAny checks if one or more mask bits are set in receiver flags.
func (flags Flags) HasAny(mask Flags) bool { return flags&mask != 0 }

// StringFlags returns human readable flag string. i.e:
//
//	"[SYN,ACK]"
//
// Flags are printed in order from LSB (FIN) to MSB (NS).
// All flags are printed with length of 3, so a NS flag will
// end with a space i.e. [ACK,NS ]
func (flags Flags) String() string {
	// Cover most common cases without heap allocating.
	switch flags {
	case 0:
		return "[]"
	case synack:
		return "[SYN,ACK]"
	case finack:
		return "[FIN,ACK]"
	case pshack:
		return "[PSH,ACK]"
	case FlagACK:
		return "[ACK]"
	case FlagSYN:
		return "[SYN]"
	case FlagFIN:
		return "[FIN]"
	case FlagRST:
		return "[RST]"
	}
	buf := make([]byte, 0, 2+3*bits.OnesCount16(uint16(flags)))
	buf = append(buf, '[')
	buf = flags.AppendFormat(buf)
	buf = append(buf, ']')
	return string(buf)
}

// AppendFormat appends a human readable flag string to b returning the extended buffer.
func (flags Flags) AppendFormat(b []byte) []byte {
	if flags == 0 {
		return b
	}
	// String Flag const
	const flaglen = 3
	const strflags = "FINSYNRSTPSHACKURGECECWRNS "
	var addcommas bool
	for flags != 0 { // written by Github Copilot- looks OK.
		i := bits.TrailingZeros16(uint16(flags))
		if addcommas {
			b = append(b, ',')
		} else {
			addcommas = true
		}
		b = append(b, strflags[i*flaglen:i*flaglen+flaglen]...)
		flags &= ^(1 << i)
	}
	return b
}

// State enumerates states a TCP connection progresses through during its lifetime.
//
//go:generate stringer -type=State -trimprefix=State
type State uint8

const (
	// CLOSED - represents no connection state at all. Is not a valid state of the TCP state machine but rather a pseudo-state pre-initialization.
	StateClosed State = iota
	// LISTEN - represents waiting for a connection request from any remote TCP and port.
	StateListen
	// SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment
	// after having both received and sent a connection request.
	StateSynRcvd
	// SYN-SENT - represents waiting for a matching connection request after having sent a connection request.
	StateSynSent
	// ESTABLISHED - represents an open connection, data received can be delivered
	// to the user.  The normal state for the data transfer phase of the connection.
	StateEstablished
	// FIN-WAIT-1 - represents waiting for a connection termination request
	// from the remote TCP, or an acknowledgment of the connection
	// termination request previously sent.
	StateFinWait1
	// FIN-WAIT-2 - represents waiting for a connection termination request
	// from the remote TCP.
	StateFinWait2
	// CLOSING - represents waiting for a connection termination request
	// acknowledgment from the remote TCP.
	StateClosing
	// TIME-WAIT - represents waiting for enough time to pass to be sure the remote
	// TCP received the acknowledgment of its connection termination request.
	StateTimeWait
	// CLOSE-WAIT - represents waiting for a connection termination request
	// from the local user.
	StateCloseWait
	// LAST-ACK - represents waiting for an acknowledgment of the
	// connection termination request previously sent to the remote TCP
	// (which includes an acknowledgment of its connection termination request).
	StateLastAck
)

// IsPreestablished returns true if the connection is in a state preceding the established state.
// Returns false for Closed pseudo state.
func (s State) IsPreestablished() bool {
	return s == StateSynRcvd || s == StateSynSent || s == StateListen
}

// IsClosing returns true if the connection is in a closing state but not yet terminated (relieved of remote connection state).
// Returns false for Closed pseudo state.
func (s State) IsClosing() bool {
	return !(s <= StateEstablished)
}

// IsClosed returns true if the connection closed and can possibly relieved of
// all state related to the remote connection. It returns true if Closed or in TimeWait.
func (s State) IsClosed() bool {
	return s == StateClosed || s == StateTimeWait
}

// IsSynchronized returns true if the connection has gone through the Established state.
func (s State) IsSynchronized() bool {
	return s >= StateEstablished
}

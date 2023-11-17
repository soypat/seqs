package seqs

import (
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	rstJump = 100
)

var (
	// errDropSegment is a flag that signals to drop a segment silently.
	errDropSegment    = errors.New("drop segment")
	errWindowTooLarge = errors.New("invalid window size > 2**16")
)

// ControlBlock is a partial Transmission Control Block (TCB) implementation as per RFC 9293
// in page 19 and clarified further in page 25. This implementation is limited to
// receiving only sequential segments. This means buffer management is left up
// entirely to the user of the ControlBlock. Use ControlBlock as the building block
// that solves Sequence Number calculation and validation in a full TCP implementation.
//
// A ControlBlock's internal state is modified by the available "System Calls" as defined in
// RFC9293, such as Close, Listen/Open, Send, and Receive.
// Sent and received data is represented with the [Segment] struct type.
type ControlBlock struct {
	// # Send Sequence Space
	//
	// 'Send' sequence numbers correspond to local data being sent.
	//
	//	     1         2          3          4
	//	----------|----------|----------|----------
	//		   SND.UNA    SND.NXT    SND.UNA
	//								+SND.WND
	//	1. old sequence numbers which have been acknowledged
	//	2. sequence numbers of unacknowledged data
	//	3. sequence numbers allowed for new data transmission
	//	4. future sequence numbers which are not yet allowed
	snd sendSpace
	// # Receive Sequence Space
	//
	// 'Receive' sequence numbers correspond to remote data being received.
	//
	//		1          2          3
	//	----------|----------|----------
	//		   RCV.NXT    RCV.NXT
	//					 +RCV.WND
	//	1 - old sequence numbers which have been acknowledged
	//	2 - sequence numbers allowed for new reception
	//	3 - future sequence numbers which are not yet allowed
	rcv    recvSpace
	rstPtr Value // RST pointer. See RFC 3540.
	// pending and state are modified by rcv* methods and Close method.
	// The pending flags are only updated if the Recv method finishes with no error.
	pending Flags
	state   State

	debuglog string
}

// sendSpace contains Send Sequence Space data. Its sequence numbers correspond to local data.
type sendSpace struct {
	ISS Value // initial send sequence number, defined locally on connection start
	UNA Value // send unacknowledged. Seqs equal to UNA and above have NOT been acked by remote. Corresponds to local data.
	NXT Value // send next. This seq and up to UNA+WND-1 are allowed to be sent. Corresponds to local data.
	// WL1 Value // segment sequence number used for last window update
	// WL2 Value // segment acknowledgment number used for last window update
	WND Size // send window defined by remote. Permitted number unacked octets in flight.
}

// recvSpace contains Receive Sequence Space data. Its sequence numbers correspond to remote data.
type recvSpace struct {
	IRS Value // initial receive sequence number, defined by remote in SYN segment received.
	NXT Value // receive next. seqs before this have been acked. this seq and up to NXT+WND-1 are allowed to be sent. Corresponds to remote data.
	WND Size  // receive window defined by local. Permitted number unacked octets in flight.
}

// Segment represents a TCP segment as the sequence number of the first octet and the length of the segment.
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

// PendingSegment calculates a suitable next segment to send from a payload length.
func (tcb *ControlBlock) PendingSegment(payloadLen int) (_ Segment, ok bool) {
	if (payloadLen == 0 && tcb.pending == 0) || (payloadLen > 0 && tcb.state != StateEstablished) {
		return Segment{}, false // No pending segment.
	}
	if payloadLen > math.MaxUint16 || Size(payloadLen) > tcb.snd.WND {
		payloadLen = int(tcb.snd.WND)
	}

	var ack Value
	if tcb.pending.HasAny(FlagACK) {
		ack = tcb.rcv.NXT
	}

	var seq Value = tcb.snd.NXT
	if tcb.pending.HasAny(FlagRST) {
		seq = tcb.rstPtr
	}

	seg := Segment{
		SEQ:     seq,
		ACK:     ack,
		WND:     tcb.rcv.WND,
		Flags:   tcb.pending,
		DATALEN: Size(payloadLen),
	}
	return seg, true
}

func (tcb *ControlBlock) rcvListen(seg Segment) (pending Flags, err error) {
	switch {
	case !seg.Flags.HasAll(FlagSYN): //|| flags.HasAny(eth.FlagTCP_ACK):
		err = errors.New("rcvListen: no SYN or unexpected flag set")
	}
	if err != nil {
		return 0, err
	}
	// Initialize all connection state:
	tcb.resetSnd(tcb.snd.ISS, seg.WND)
	tcb.resetRcv(tcb.rcv.WND, seg.SEQ)

	// We must respond with SYN|ACK frame after receiving SYN in listen state (three way handshake).
	tcb.pending = synack
	tcb.state = StateSynRcvd
	return synack, nil
}

func (tcb *ControlBlock) rcvSynSent(seg Segment) (pending Flags, err error) {
	hasSyn := seg.Flags.HasAny(FlagSYN)
	hasAck := seg.Flags.HasAny(FlagACK)
	switch {
	case !hasSyn:
		err = errors.New("rcvSynSent: expected SYN")

	case hasAck && seg.ACK != tcb.snd.UNA+1:
		err = errors.New("rcvSynSent: bad seg.ack")
	}
	if err != nil {
		return 0, err
	}

	if hasAck {
		tcb.state = StateEstablished
		pending = FlagACK
		tcb.resetRcv(tcb.rcv.WND, seg.SEQ)
	} else {
		// Simultaneous connection sync edge case.
		pending = synack
		tcb.state = StateSynRcvd
		tcb.resetSnd(tcb.snd.ISS, seg.WND)
		tcb.resetRcv(tcb.rcv.WND, seg.SEQ)
	}
	return pending, nil
}

func (tcb *ControlBlock) rcvSynRcvd(seg Segment) (pending Flags, err error) {
	switch {
	case !seg.Flags.HasAll(FlagACK):
		err = errors.New("rcvSynRcvd: expected ACK")
	case seg.ACK != tcb.snd.UNA+1:
		err = errors.New("rcvSynRcvd: bad seg.ack")
	}
	if err != nil {
		return 0, err
	}
	tcb.state = StateEstablished
	return FlagACK, nil
}

func (tcb *ControlBlock) rcvEstablished(seg Segment) (pending Flags, err error) {
	flags := seg.Flags
	pending = FlagACK
	if flags.HasAny(FlagFIN) {
		// See Figure 5: TCP Connection State Diagram of RFC 9293.
		tcb.state = StateCloseWait
	}
	return pending, nil
}

func (tcb *ControlBlock) rcvFinWait1(seg Segment) (pending Flags, err error) {
	flags := seg.Flags
	if !flags.HasAny(FlagACK) {
		return 0, errors.New("rcvFinWait1: expected ACK")
	} else if flags.HasAny(FlagFIN) {
		tcb.state = StateClosing // Simultaneous close. See figure 13 of RFC 9293.
	} else {
		tcb.state = StateFinWait2
	}

	return FlagACK, nil
}

func (tcb *ControlBlock) rcvFinWait2(seg Segment) (pending Flags, err error) {
	if !seg.Flags.HasAll(finack) {
		return pending, errors.New("rcvFinWait2: expected FIN|ACK")
	}
	tcb.state = StateTimeWait
	return FlagACK, nil
}

func (tcb *ControlBlock) resetSnd(localISS Value, remoteWND Size) {
	tcb.snd = sendSpace{
		ISS: localISS,
		UNA: localISS,
		NXT: localISS,
		WND: remoteWND,
		// UP, WL1, WL2 defaults to zero values.
	}
}

func (tcb *ControlBlock) resetRcv(localWND Size, remoteISS Value) {
	tcb.rcv = recvSpace{
		IRS: remoteISS,
		NXT: remoteISS,
		WND: localWND,
	}
}

func (tcb *ControlBlock) validateIncomingSegment(seg Segment) (err error) {
	const errPfx = "reject incoming seg: "
	flags := seg.Flags
	hasAck := flags.HasAll(FlagACK)
	// Short circuit SEQ checks if SYN present since the incoming segment initializes connection.
	checkSEQ := !flags.HasAny(FlagSYN)
	established := tcb.state == StateEstablished
	preestablished := tcb.state.preEstablished()
	acksOld := hasAck && !LessThan(tcb.snd.UNA, seg.ACK)
	acksUnsentData := hasAck && !LessThanEq(seg.ACK, tcb.snd.NXT)
	ctlOrDataSegment := established && flags.HasAny(FlagFIN|FlagRST|FlagPSH)
	// See section 3.4 of RFC 9293 for more on these checks.
	switch {
	case seg.WND > math.MaxUint16:
		err = errors.New(errPfx + "wnd > 2**16")
	case tcb.state == StateClosed:
		err = io.ErrClosedPipe

	case checkSEQ && !InWindow(seg.SEQ, tcb.rcv.NXT, tcb.rcv.WND):
		err = errors.New(errPfx + "seq not in receive window")

	case checkSEQ && !InWindow(seg.Last(), tcb.rcv.NXT, tcb.rcv.WND):
		err = errors.New(errPfx + "last not in receive window")

	case checkSEQ && seg.SEQ != tcb.rcv.NXT:
		err = errors.New(errPfx + "seq != rcv.nxt (use sequential segments)")
	}
	if err != nil {
		return err
	}

	// Drop-segment checks.
	switch {
	// Special treatment of duplicate ACKs on established connection and of ACKs of unsent data.
	// https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4-2.5.2.2.2.3.2.1
	case established && acksOld && !ctlOrDataSegment:
		err = errDropSegment
		tcb.pending = 0 // Completely ignore duplicate ACKs.
		tcb.debuglog += fmt.Sprintf("rcv %s: duplicate ACK %x\n", tcb.state, seg.ACK)

	case established && acksUnsentData:
		err = errDropSegment
		tcb.pending = FlagACK // Send ACK for unsent data.
		tcb.debuglog += fmt.Sprintf("rcv %s: ACK %x of unsent data\n", tcb.state, seg.ACK)

	case preestablished && (acksOld || acksUnsentData):
		err = errDropSegment
		tcb.pending = FlagRST
		tcb.rstPtr = seg.ACK
		tcb.resetSnd(tcb.snd.ISS, seg.WND)
		tcb.debuglog += fmt.Sprintf("rcv %s: RST %x of old data\n", tcb.state, seg.ACK)

	case preestablished && flags.HasAny(FlagRST):
		err = errDropSegment
		tcb.pending = 0
		tcb.state = StateListen
		tcb.resetSnd(tcb.snd.ISS+rstJump, tcb.snd.WND)
		tcb.resetRcv(tcb.rcv.WND, 3_14159_2653)
		tcb.debuglog += fmt.Sprintf("rcv %s: remote RST\n", tcb.state)
	}
	return err
}

func (tcb *ControlBlock) validateOutgoingSegment(seg Segment) (err error) {
	hasAck := seg.Flags.HasAny(FlagACK)
	checkSeq := !seg.Flags.HasAny(FlagRST)
	const errPfx = "invalid out segment: "
	seglast := seg.Last()
	switch {
	case tcb.state == StateClosed:
		err = io.ErrClosedPipe
	case seg.WND > math.MaxUint16:
		err = errWindowTooLarge
	case hasAck && seg.ACK != tcb.rcv.NXT:
		err = errors.New(errPfx + "ack != rcv.nxt")

	case checkSeq && !InWindow(seg.SEQ, tcb.snd.NXT, tcb.snd.WND):
		err = errors.New(errPfx + "seq not in send window")

	case checkSeq && !InWindow(seglast, tcb.snd.NXT, tcb.snd.WND):
		err = errors.New(errPfx + "last not in send window")
	}
	return err
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

	// The union of SYN and ACK flags is commonly found throughout the specification, so we define a shorthand.
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
	if flags == 0 {
		return "[]"
	}
	// String Flag const
	const flaglen = 3
	var flagbuff [2 + (flaglen+1)*9]byte
	const strflags = "FINSYNRSTPSHACKURGECECWRNS "
	n := 0
	for i := 0; i*3 < len(strflags)-flaglen; i++ {
		if flags&(1<<i) != 0 {
			if n == 0 {
				flagbuff[0] = '['
				n++
			} else {
				flagbuff[n] = ','
				n++
			}
			copy(flagbuff[n:n+3], []byte(strflags[i*flaglen:i*flaglen+flaglen]))
			n += 3
		}
	}
	if n > 0 {
		flagbuff[n] = ']'
		n++
	}
	return string(flagbuff[:n])
}

// State enumerates states a TCP connection progresses through during its lifetime.
//
//go:generate stringer -type=State -trimprefix=State
type State uint8

const (
	// CLOSED - represents no connection state at all.
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

func (s State) preEstablished() bool {
	return s == StateSynRcvd || s == StateSynSent || s == StateListen
}

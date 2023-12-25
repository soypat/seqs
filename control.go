package seqs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/bits"
	"net"

	"github.com/soypat/seqs/internal"
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
	rcv recvSpace
	// When FlagRST is set in pending flags rstPtr will contain the sequence number of the RST segment to make it "believable" (See RFC9293)
	rstPtr Value
	// pending is the queue of pending flags to be sent in the next 2 segments.
	// On a call to Send the queue is advanced and flags set in the segment are unset.
	// The second position of the queue is used for FIN segments.
	pending      [2]Flags
	state        State
	challengeAck bool
	islistener   bool
	log          *slog.Logger
}

// sendSpace contains Send Sequence Space data. Its sequence numbers correspond to local data.
type sendSpace struct {
	ISS Value // initial send sequence number, defined locally on connection start
	UNA Value // send unacknowledged. Seqs equal to UNA and above have NOT been acked by remote. Corresponds to local data.
	NXT Value // send next. This seq and up to UNA+WND-1 are allowed to be sent. Corresponds to local data.
	WND Size  // send window defined by remote. Permitted number of local unacked octets in flight.
	// WL1 Value // segment sequence number used for last window update
	// WL2 Value // segment acknowledgment number used for last window update
}

// recvSpace contains Receive Sequence Space data. Its sequence numbers correspond to remote data.
type recvSpace struct {
	IRS Value // initial receive sequence number, defined by remote in SYN segment received.
	NXT Value // receive next. seqs before this have been acked. this seq and up to NXT+WND-1 are allowed to be sent. Corresponds to remote data.
	WND Size  // receive window defined by local. Permitted number of remote unacked octets in flight.
}

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

// PendingSegment calculates a suitable next segment to send from a payload length.
// It does not modify the ControlBlock state or pending segment queue.
func (tcb *ControlBlock) PendingSegment(payloadLen int) (_ Segment, ok bool) {
	pending := tcb.pending[0]
	established := tcb.state == StateEstablished
	if !established && tcb.state != StateCloseWait {
		payloadLen = 0 // Can't send data if not established.
	}
	if pending == 0 && payloadLen == 0 {
		return Segment{}, false // No pending segment.
	}
	if payloadLen > math.MaxUint16 || Size(payloadLen) > tcb.snd.WND {
		payloadLen = int(tcb.snd.WND)
	}

	if established {
		pending |= FlagACK // ACK is always set in established state. Not in RFC9293 but somehow expected?
	} else {
		payloadLen = 0 // Can't send data if not established.
	}

	var ack Value
	if pending.HasAny(FlagACK) {
		ack = tcb.rcv.NXT
	}

	var seq Value = tcb.snd.NXT
	if pending.HasAny(FlagRST) {
		seq = tcb.rstPtr
	}

	if tcb.challengeAck {
		tcb.challengeAck = false
		seq = tcb.snd.NXT
		ack = tcb.rcv.NXT
		pending = FlagACK
	}

	seg := Segment{
		SEQ:     seq,
		ACK:     ack,
		WND:     tcb.rcv.WND,
		Flags:   pending,
		DATALEN: Size(payloadLen),
	}
	return seg, true
}

// HasPending returns true if there is a pending control segment to send. Calls to Send will advance the pending queue.
func (tcb *ControlBlock) HasPending() bool { return tcb.pending[0] != 0 }

func (tcb *ControlBlock) rcvListen(seg Segment) (pending Flags, err error) {
	switch {
	case !seg.Flags.HasAll(FlagSYN):
		err = errExpectedSYN
	}
	if err != nil {
		return 0, err
	}
	// Initialize all connection state:
	tcb.resetSnd(tcb.snd.ISS, seg.WND)
	tcb.resetRcv(tcb.rcv.WND, seg.SEQ)

	// We must respond with SYN|ACK frame after receiving SYN in listen state (three way handshake).
	tcb.pending[0] = synack
	tcb.state = StateSynRcvd
	return synack, nil
}

func (tcb *ControlBlock) rcvSynSent(seg Segment) (pending Flags, err error) {
	hasSyn := seg.Flags.HasAny(FlagSYN)
	hasAck := seg.Flags.HasAny(FlagACK)
	switch {
	case !hasSyn:
		err = errExpectedSYN

	case hasAck && seg.ACK != tcb.snd.UNA+1:
		err = errBadSegack
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
	// case !seg.Flags.HasAll(FlagACK):
	// 	err = errors.New("rcvSynRcvd: expected ACK")
	case seg.ACK != tcb.snd.UNA+1:
		err = errBadSegack
	}
	if err != nil {
		return 0, err
	}
	tcb.state = StateEstablished
	return 0, nil
}

func (tcb *ControlBlock) rcvEstablished(seg Segment) (pending Flags, err error) {
	flags := seg.Flags

	dataToAck := seg.DATALEN > 0
	hasFin := flags.HasAny(FlagFIN)
	if dataToAck || hasFin {
		pending = FlagACK
		if hasFin {
			// See Figure 5: TCP Connection State Diagram of RFC 9293.
			tcb.state = StateCloseWait
			tcb.pending[1] = FlagFIN // Queue FIN for after the CloseWait ACK.
		}
	}

	return pending, nil
}

func (tcb *ControlBlock) rcvFinWait1(seg Segment) (pending Flags, err error) {
	flags := seg.Flags
	if !flags.HasAny(FlagACK) {
		return 0, errFinwaitExpectedACK
	} else if flags.HasAny(FlagFIN) {
		tcb.state = StateClosing // Simultaneous close. See figure 13 of RFC 9293.
		pending = FlagACK
	} else {
		tcb.state = StateFinWait2
		pending = FlagACK
	}
	return pending, nil
}

func (tcb *ControlBlock) rcvFinWait2(seg Segment) (pending Flags, err error) {
	if !seg.Flags.HasAll(finack) {
		return pending, errFinwaitExpectedFinack
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
	flags := seg.Flags
	hasAck := flags.HasAll(FlagACK)
	// Short circuit SEQ checks if SYN present since the incoming segment initializes connection.
	checkSEQ := !flags.HasAny(FlagSYN)
	established := tcb.state == StateEstablished
	preestablished := tcb.state.IsPreestablished()
	acksOld := hasAck && !LessThan(tcb.snd.UNA, seg.ACK)
	acksUnsentData := hasAck && !LessThanEq(seg.ACK, tcb.snd.NXT)
	ctlOrDataSegment := established && (seg.DATALEN > 0 || flags.HasAny(FlagFIN|FlagRST))
	// See section 3.4 of RFC 9293 for more on these checks.
	switch {
	case seg.WND > math.MaxUint16:
		err = errWindowOverflow
	case tcb.state == StateClosed:
		err = io.ErrClosedPipe

	case checkSEQ && !InWindow(seg.SEQ, tcb.rcv.NXT, tcb.rcv.WND):
		err = errSeqNotInWindow

	case checkSEQ && !InWindow(seg.Last(), tcb.rcv.NXT, tcb.rcv.WND):
		err = errLastNotInWindow

	case checkSEQ && seg.SEQ != tcb.rcv.NXT:
		// This part diverts from TCB as described in RFC 9293. We want to support
		// only sequential segments to keep implementation simple and maintainable. See SHLD-31.
		err = errRequireSequential
	}
	if err != nil {
		return err
	}
	if flags.HasAny(FlagRST) {
		return tcb.handleRST(seg.SEQ)
	}

	isDebug := tcb.logenabled(slog.LevelDebug)
	// Drop-segment checks.
	switch {
	// Special treatment of duplicate ACKs on established connection and of ACKs of unsent data.
	// https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4-2.5.2.2.2.3.2.1
	case established && acksOld && !ctlOrDataSegment:
		err = errDropSegment
		tcb.pending[0] &= FlagFIN // Completely ignore duplicate ACKs but do not erase fin bit.
		if isDebug {
			tcb.debug("rcv:ACK-dup", slog.String("state", tcb.state.String()),
				slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.una", uint64(tcb.snd.UNA)))
		}

	case established && acksUnsentData:
		err = errDropSegment
		tcb.pending[0] = FlagACK // Send ACK for unsent data.
		if isDebug {
			tcb.debug("rcv:ACK-unsent", slog.String("state", tcb.state.String()),
				slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)))
		}

	case preestablished && (acksOld || acksUnsentData):
		err = errDropSegment
		tcb.pending[0] = FlagRST
		tcb.rstPtr = seg.ACK
		tcb.resetSnd(tcb.snd.ISS, seg.WND)
		if isDebug {
			tcb.debug("rcv:RST-old", slog.String("state", tcb.state.String()), slog.Uint64("ack", uint64(seg.ACK)))
		}
	}
	return err
}

func (tcb *ControlBlock) validateOutgoingSegment(seg Segment) (err error) {
	hasAck := seg.Flags.HasAny(FlagACK)
	checkSeq := !seg.Flags.HasAny(FlagRST)
	seglast := seg.Last()
	switch {
	case tcb.state == StateClosed:
		err = io.ErrClosedPipe
	case seg.WND > math.MaxUint16:
		err = errWindowTooLarge
	case hasAck && seg.ACK != tcb.rcv.NXT:
		err = errAckNotNext

	case checkSeq && !InWindow(seg.SEQ, tcb.snd.NXT, tcb.snd.WND):
		err = errSeqNotInWindow

	case checkSeq && !InWindow(seglast, tcb.snd.NXT, tcb.snd.WND):
		err = errLastNotInWindow
	}
	return err
}

// close sets ControlBlock state to closed and resets all sequence numbers and pending flag.
func (tcb *ControlBlock) close() {
	tcb.state = StateClosed
	tcb.pending = [2]Flags{}
	tcb.resetRcv(0, 0)
	tcb.resetSnd(0, 0)
	tcb.debug("tcb:close")
}

// hasIRS checks if the ControlBlock has received a valid initial sequence number (IRS).
func (tcb *ControlBlock) hasIRS() bool {
	return tcb.isOpen() && tcb.state != StateSynSent && tcb.state != StateListen
}

// isOpen checks if the ControlBlock is in a state that allows sending and/or receiving data.
func (tcb *ControlBlock) isOpen() bool {
	return tcb.state != StateClosed && tcb.state != StateTimeWait
}

func (tcb *ControlBlock) handleRST(seq Value) error {
	tcb.debug("rcv:RST", slog.String("state", tcb.state.String()))
	if seq != tcb.rcv.NXT {
		// See RFC9293: If the RST bit is set and the sequence number does not exactly match the next expected sequence value, yet is within the current receive window, TCP endpoints MUST send an acknowledgment (challenge ACK).
		tcb.challengeAck = true
		tcb.pending[0] |= FlagACK
		return errDropSegment
	}
	if tcb.state.IsPreestablished() {
		tcb.pending[0] = 0
		tcb.state = StateListen
		tcb.resetSnd(tcb.snd.ISS+rstJump, tcb.snd.WND)
		tcb.resetRcv(tcb.rcv.WND, 3_14159_2653^tcb.rcv.IRS)
	} else {
		tcb.close() // Enter closed state and return.
		return net.ErrClosed
	}
	return errDropSegment
}

func (tcb *ControlBlock) logenabled(lvl slog.Level) bool {
	return internal.HeapAllocDebugging || (tcb.log != nil && tcb.log.Handler().Enabled(context.Background(), lvl))
}

func (tcb *ControlBlock) debug(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(tcb.log, slog.LevelDebug, msg, attrs...)
}

func (tcb *ControlBlock) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(tcb.log, internal.LevelTrace, msg, attrs...)
}

func (tcb *ControlBlock) logerr(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(tcb.log, slog.LevelError, msg, attrs...)
}

func (tcb *ControlBlock) traceSnd(msg string) {
	tcb.trace(msg,
		slog.String("state", tcb.state.String()),
		slog.Uint64("pend", uint64(tcb.pending[0])),
		slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)),
		slog.Uint64("snd.una", uint64(tcb.snd.UNA)),
		slog.Uint64("snd.wnd", uint64(tcb.snd.WND)),
	)
}

func (tcb *ControlBlock) traceRcv(msg string) {
	tcb.trace(msg,
		slog.String("state", tcb.state.String()),
		slog.Uint64("rcv.nxt", uint64(tcb.rcv.NXT)),
		slog.Uint64("rcv.wnd", uint64(tcb.rcv.WND)),
		slog.Bool("challenge", tcb.challengeAck),
	)
}

func (tcb *ControlBlock) traceSeg(msg string, seg Segment) {
	tcb.trace(msg,
		slog.Uint64("seg.seq", uint64(seg.SEQ)),
		slog.Uint64("seg.ack", uint64(seg.ACK)),
		slog.Uint64("seg.wnd", uint64(seg.WND)),
		slog.Uint64("seg.flags", uint64(seg.Flags)),
		slog.Uint64("seg.data", uint64(seg.DATALEN)),
	)
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
	if flags == 0 {
		return "[]"
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

// IsSynchronized returns true
func (s State) IsSynchronized() bool {
	return s >= StateEstablished
}

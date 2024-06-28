package seqs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
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

// ControlBlock is a partial Transmission Control Block (TCB) implementation as
// per RFC 9293 in section 3.3.1. In contrast with the description in RFC9293,
// this implementation is limited to receiving only sequential segments.
// This means buffer management is left up entirely to the user of the ControlBlock.
// Use ControlBlock as the building block that solves Sequence Number calculation
// and validation in a full TCP implementation.
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

// inFlight returns amount of unacked bytes sent out.
func (snd *sendSpace) inFlight() Size {
	return Sizeof(snd.UNA, snd.NXT)
}

// maxSend returns maximum segment datalength receivable by remote peer.
func (snd *sendSpace) maxSend() Size {
	return snd.WND - snd.inFlight()
}

// recvSpace contains Receive Sequence Space data. Its sequence numbers correspond to remote data.
type recvSpace struct {
	IRS Value // initial receive sequence number, defined by remote in SYN segment received.
	NXT Value // receive next. seqs before this have been acked. this seq and up to NXT+WND-1 are allowed to be sent. Corresponds to remote data.
	WND Size  // receive window defined by local. Permitted number of remote unacked octets in flight.
}

// PendingSegment calculates a suitable next segment to send from a payload length.
// It does not modify the ControlBlock state or pending segment queue.
func (tcb *ControlBlock) PendingSegment(payloadLen int) (_ Segment, ok bool) {
	if tcb.challengeAck {
		tcb.challengeAck = false
		return Segment{SEQ: tcb.snd.NXT, ACK: tcb.rcv.NXT, Flags: FlagACK, WND: tcb.rcv.WND}, true
	}
	pending := tcb.pending[0]
	established := tcb.state == StateEstablished
	if !established && tcb.state != StateCloseWait {
		payloadLen = 0 // Can't send data if not established.
	}
	if pending == 0 && payloadLen == 0 {
		return Segment{}, false // No pending segment.
	}

	// Limit payload to what send window allows.
	inFlight := tcb.snd.inFlight()
	_ = inFlight
	maxPayload := tcb.snd.maxSend()
	if payloadLen > int(maxPayload) {
		if maxPayload == 0 && !tcb.pending[0].HasAny(FlagFIN|FlagRST|FlagSYN) {
			return Segment{}, false
		} else if maxPayload > tcb.snd.WND {
			panic("seqs: bad calculation")
		}
		payloadLen = int(maxPayload)
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

	seg := Segment{
		SEQ:     seq,
		ACK:     ack,
		WND:     tcb.rcv.WND,
		Flags:   pending,
		DATALEN: Size(payloadLen),
	}
	tcb.traceSeg("tcb:pending-out", seg)
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
	hasFin := flags&FlagFIN != 0
	hasAck := flags&FlagACK != 0
	switch {
	case hasFin && hasAck && seg.ACK == tcb.snd.NXT:
		// Special case: Server sent a FINACK response to our FIN so we enter TimeWait directly.
		// We have to check ACK against send NXT to avoid simultaneous close sequence edge case.
		tcb.state = StateTimeWait
	case hasFin:
		tcb.state = StateClosing
	case hasAck:
		// TODO(soypat): Check if this branch does NOT need ACK queued. Online flowcharts say not needed.
		tcb.state = StateFinWait2
	default:
		return 0, errFinwaitExpectedACK
	}
	pending = FlagACK
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
	zeroWindowOK := tcb.rcv.WND == 0 && seg.DATALEN == 0 && seg.SEQ == tcb.rcv.NXT
	// See section 3.4 of RFC 9293 for more on these checks.
	switch {
	case seg.WND > math.MaxUint16:
		err = errWindowOverflow
	case tcb.state == StateClosed:
		err = io.ErrClosedPipe

	case checkSEQ && tcb.rcv.WND == 0 && seg.DATALEN > 0 && seg.SEQ == tcb.rcv.NXT:
		err = errZeroWindow

	case checkSEQ && !InWindow(seg.SEQ, tcb.rcv.NXT, tcb.rcv.WND) && !zeroWindowOK:
		err = errSeqNotInWindow

	case checkSEQ && !InWindow(seg.Last(), tcb.rcv.NXT, tcb.rcv.WND) && !zeroWindowOK:
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
	// Extra check for when send Window is zero and no data is being sent.
	zeroWindowOK := tcb.snd.WND == 0 && seg.DATALEN == 0 && seg.SEQ == tcb.snd.NXT
	outOfWindow := checkSeq && !InWindow(seg.SEQ, tcb.snd.NXT, tcb.snd.WND) &&
		!zeroWindowOK
	switch {
	case tcb.state == StateClosed:
		err = io.ErrClosedPipe
	case seg.WND > math.MaxUint16:
		err = errWindowTooLarge
	case hasAck && seg.ACK != tcb.rcv.NXT:
		err = errAckNotNext

	case outOfWindow:
		if tcb.snd.WND == 0 {
			err = errZeroWindow
		} else {
			err = errSeqNotInWindow
		}

	case seg.DATALEN > 0 && (tcb.state == StateFinWait1 || tcb.state == StateFinWait2):
		err = errConnectionClosing // Case 1: No further SENDs from the user will be accepted by the TCP implementation.

	case checkSeq && tcb.snd.WND == 0 && seg.DATALEN > 0 && seg.SEQ == tcb.snd.NXT:
		err = errZeroWindow

	case checkSeq && !InWindow(seglast, tcb.snd.NXT, tcb.snd.WND) && !zeroWindowOK:
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

func (tcb *ControlBlock) logattrs(lvl slog.Level, msg string, attrs ...slog.Attr) {
	internal.LogAttrs(tcb.log, lvl, msg, attrs...)
}

func (tcb *ControlBlock) debug(msg string, attrs ...slog.Attr) {
	tcb.logattrs(slog.LevelDebug, msg, attrs...)
}

func (tcb *ControlBlock) trace(msg string, attrs ...slog.Attr) {
	tcb.logattrs(internal.LevelTrace, msg, attrs...)
}

func (tcb *ControlBlock) logerr(msg string, attrs ...slog.Attr) {
	tcb.logattrs(slog.LevelError, msg, attrs...)
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
	if tcb.logenabled(internal.LevelTrace) {
		tcb.trace(msg,
			slog.Uint64("seg.seq", uint64(seg.SEQ)),
			slog.Uint64("seg.ack", uint64(seg.ACK)),
			slog.Uint64("seg.wnd", uint64(seg.WND)),
			slog.String("seg.flags", seg.Flags.String()),
			slog.Uint64("seg.data", uint64(seg.DATALEN)),
		)
	}
}

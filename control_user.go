package seqs

import (
	"errors"
	"log/slog"
	"math"

	"github.com/soypat/seqs/internal"
)

// Functions in this file correspond loosely to the API described in
// https://datatracker.ietf.org/doc/html/rfc9293#name-user-tcp-interface
// The main difference is that this API is built around the ControlBlock
// which is a small part of the whole TCP state machine.

var (
	errTCBNotClosed          = errors.New("TCB not closed")
	errInvalidState          = errors.New("invalid state")
	errConnNotexist          = errors.New("connection does not exist")
	errConnectionClosing     = errors.New("connection closing")
	errExpectedSYN           = errors.New("seqs:expected SYN")
	errBadSegack             = errors.New("seqs:bad segack")
	errFinwaitExpectedACK    = errors.New("seqs:finwait1 expected ACK")
	errFinwaitExpectedFinack = errors.New("seqs:finwait2 expected FINACK")

	errWindowOverflow    = newRejectErr("wnd > 2**16")
	errSeqNotInWindow    = newRejectErr("seq not in snd/rcv.wnd")
	errZeroWindow        = newRejectErr("zero window")
	errLastNotInWindow   = newRejectErr("last not in snd/rcv.wnd")
	errRequireSequential = newRejectErr("seq != rcv.nxt (require sequential segments)")
	errAckNotNext        = newRejectErr("ack != snd.nxt")
)

func newRejectErr(err string) *RejectError { return &RejectError{err: "reject in/out seg: " + err} }

// RejectError represents an error that arises during admission of a segment into the
// Transmission Control Block logic in which the packet cannot be processed by the TCB.
type RejectError struct {
	err string
}

func (e *RejectError) Error() string { return e.err }

// State returns the current state of the connection.
func (tcb *ControlBlock) State() State { return tcb.state }

// Open implements a passive/active opening of a connection.
// state must be StateListen or StateSynSent.
func (tcb *ControlBlock) Open(iss Value, wnd Size, state State) (err error) {
	switch {
	case tcb.state != StateClosed && tcb.state != StateListen:
		err = errTCBNotClosed
	case state != StateListen && state != StateSynSent:
		err = errInvalidState
	case wnd > math.MaxUint16:
		err = errWindowTooLarge
	}
	if err != nil {
		tcb.logerr("tcb:open", slog.String("err", err.Error()))
		return err
	}
	tcb.state = state
	tcb.resetRcv(wnd, 0)
	tcb.resetSnd(iss, 1)
	tcb.pending = [2]Flags{}
	if state == StateSynSent {
		tcb.pending[0] = FlagSYN
	}
	tcb.trace("tcb:open", slog.String("state", tcb.state.String()))
	return nil
}

// Close implements a passive/active closing of a connection. It does not immediately
// delete the TCB but initiates the process so that pending outgoing segments initiate
// the closing process. After a call to Close users should not send more data.
// Close returns an error if the connection is already closed or closing.
func (tcb *ControlBlock) Close() (err error) {
	// See RFC 9293: 3.10.4 CLOSE call.
	switch tcb.state {
	case StateClosed:
		err = errConnNotexist
	case StateCloseWait:
		tcb.state = StateLastAck
		tcb.pending = [2]Flags{FlagFIN, FlagACK}
	case StateListen, StateSynSent:
		tcb.close()
	case StateSynRcvd, StateEstablished:
		// We suppose user has no more pending data to send, so we flag FIN to be sent.
		// Users of this API should call Close only when they have no more data to send.
		tcb.pending[0] = (tcb.pending[0] & FlagACK) | FlagFIN
	case StateFinWait2, StateTimeWait:
		err = errConnectionClosing
	default:
		err = errInvalidState
	}
	if err == nil {
		tcb.trace("tcb:close", slog.String("state", tcb.state.String()))
	} else {
		tcb.logerr("tcb:close", slog.String("err", err.Error()))
	}
	return err
}

// Send processes a segment that is being sent to the network. It updates the TCB
// if there is no error.
func (tcb *ControlBlock) Send(seg Segment) error {
	err := tcb.validateOutgoingSegment(seg)
	if err != nil {
		tcb.traceSnd("tcb:snd.reject")
		tcb.traceSeg("tcb:snd.reject", seg)
		tcb.logerr("tcb:snd.reject", slog.String("err", err.Error()))
		return err
	}

	hasFIN := seg.Flags.HasAny(FlagFIN)
	hasACK := seg.Flags.HasAny(FlagACK)
	var newPending Flags
	switch tcb.state {
	case StateSynRcvd:
		if hasFIN {
			tcb.state = StateFinWait1 // RFC 9293: 3.10.4 CLOSE call.
		}
	case StateClosing:
		if hasACK {
			tcb.state = StateTimeWait
		}
	case StateEstablished:
		if hasFIN {
			tcb.state = StateFinWait1
		}
	case StateCloseWait:
		if hasFIN {
			tcb.state = StateLastAck
		} else if hasACK {
			newPending = finack // Queue finack.
		}
	}

	// Advance pending flags queue.
	tcb.pending[0] &^= seg.Flags
	if tcb.pending[0] == 0 {
		// Ensure we don't queue a FINACK if we have already sent a FIN.
		tcb.pending = [2]Flags{tcb.pending[1] &^ (seg.Flags & (FlagFIN)), 0}
	}
	tcb.pending[0] |= newPending

	// The segment is valid, we can update TCB state.
	seglen := seg.LEN()
	tcb.snd.NXT.UpdateForward(seglen)
	tcb.rcv.WND = seg.WND

	if tcb.logenabled(internal.LevelTrace) {
		tcb.traceSnd("tcb:snd")
		tcb.traceSeg("tcb:snd", seg)
	}

	return nil
}

// Recv processes a segment that is being received from the network. It updates the TCB
// if there is no error. The ControlBlock can only receive segments that are the next
// expected sequence number which means the caller must handle the out-of-order case
// and buffering that comes with it.
func (tcb *ControlBlock) Recv(seg Segment) (err error) {
	err = tcb.validateIncomingSegment(seg)
	if err != nil {
		tcb.traceRcv("tcb:rcv.reject")
		tcb.traceSeg("tcb:rcv.reject", seg)
		tcb.logerr("tcb:rcv.reject", slog.String("err", err.Error()))
		return err
	}
	prevNxt := tcb.snd.NXT
	var pending Flags
	switch tcb.state {
	case StateListen:
		pending, err = tcb.rcvListen(seg)
	case StateSynSent:
		pending, err = tcb.rcvSynSent(seg)
	case StateSynRcvd:
		pending, err = tcb.rcvSynRcvd(seg)
	case StateEstablished:
		pending, err = tcb.rcvEstablished(seg)
	case StateFinWait1:
		pending, err = tcb.rcvFinWait1(seg)
	case StateFinWait2:
		pending, err = tcb.rcvFinWait2(seg)
	case StateCloseWait:
	case StateLastAck:
		if seg.Flags.HasAny(FlagACK) {
			tcb.close()
		}
	case StateClosing:
		// Thanks to @knieriem for finding and reporting this bug.
		if seg.Flags.HasAny(FlagACK) {
			tcb.state = StateTimeWait
		}
	default:
		panic("unexpected recv state:" + tcb.state.String())
	}
	if err != nil {
		return err
	}

	tcb.pending[0] |= pending
	if prevNxt != 0 && tcb.snd.NXT != prevNxt && tcb.logenabled(slog.LevelDebug) {
		tcb.debug("tcb:snd.nxt-change", slog.String("state", tcb.state.String()),
			slog.Uint64("seg.ack", uint64(seg.ACK)), slog.Uint64("snd.nxt", uint64(tcb.snd.NXT)),
			slog.Uint64("prevnxt", uint64(prevNxt)), slog.Uint64("seg.seq", uint64(seg.SEQ)))
	}

	// We accept the segment and update TCB state.
	tcb.snd.WND = seg.WND
	if seg.Flags.HasAny(FlagACK) {
		tcb.snd.UNA = seg.ACK
	}
	seglen := seg.LEN()
	tcb.rcv.NXT.UpdateForward(seglen)

	if tcb.logenabled(internal.LevelTrace) {
		tcb.traceRcv("tcb:rcv")
		tcb.traceSeg("recv:seg", seg)
	}
	return err
}

// RecvNext returns the next sequence number expected to be received from remote.
// This implementation will reject segments that are not the next expected sequence.
// RecvNext returns 0 before StateSynRcvd.
func (tcb *ControlBlock) RecvNext() Value { return tcb.rcv.NXT }

// RecvWindow returns the receive window size. If connection is closed will return 0.
func (tcb *ControlBlock) RecvWindow() Size { return tcb.rcv.WND }

// ISS returns the initial sequence number of the connection that was defined on a call to Open by user.
func (tcb *ControlBlock) ISS() Value { return tcb.snd.ISS }

// MaxInFlightData returns the maximum size of a segment that can be sent by taking into account
// the send window size and the unacked data. Returns 0 before StateSynRcvd.
func (tcb *ControlBlock) MaxInFlightData() Size {
	if !tcb.hasIRS() {
		return 0 // SYN not yet received.
	}
	unacked := Sizeof(tcb.snd.UNA, tcb.snd.NXT)
	return tcb.snd.WND - unacked - 1 // TODO: is this -1 supposed to be here?
}

// SetWindow sets the local receive window size. This represents the maximum amount of data
// that is permitted to be in flight.
func (tcb *ControlBlock) SetRecvWindow(wnd Size) {
	tcb.rcv.WND = wnd
}

// SetLogger sets the logger to be used by the ControlBlock.
func (tcb *ControlBlock) SetLogger(log *slog.Logger) {
	tcb.log = log
}

// IncomingIsKeepalive checks if an incoming segment is a keepalive segment.
// Segments which are keepalives should not be passed into Recv or Send methods.
func (tcb *ControlBlock) IncomingIsKeepalive(incomingSegment Segment) bool {
	return incomingSegment.SEQ == tcb.rcv.NXT-1 &&
		incomingSegment.Flags == FlagACK &&
		incomingSegment.ACK == tcb.snd.NXT && incomingSegment.DATALEN == 0
}

// MakeKeepalive creates a TCP keepalive segment. This segment
// should not be passed into Recv or Send methods.
func (tcb *ControlBlock) MakeKeepalive() Segment {
	return Segment{
		SEQ:     tcb.snd.NXT - 1,
		ACK:     tcb.rcv.NXT,
		Flags:   FlagACK,
		WND:     tcb.rcv.WND,
		DATALEN: 0,
	}
}

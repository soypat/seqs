package seqs

import (
	"errors"
	"fmt"
	"math"
)

// Functions in this file correspond loosely to the API described in
// https://datatracker.ietf.org/doc/html/rfc9293#name-user-tcp-interface
// The main difference is that this API is built around the ControlBlock
// which is a small part of the whole TCP state machine.

// State returns the current state of the connection.
func (tcb *ControlBlock) State() State { return tcb.state }

// Open implements a passive/active opening of a connection.
// state must be StateListen or StateSynSent.
func (tcb *ControlBlock) Open(iss Value, wnd Size, state State) (err error) {
	switch {
	case tcb.state != StateClosed && tcb.state != StateListen:
		err = errors.New("close ControlBlock before opening")
	case state != StateListen && state != StateSynSent:
		err = errors.New("invalid state argument")
	case wnd > math.MaxUint16:
		err = errWindowTooLarge
	}
	if err != nil {
		return err
	}
	tcb.state = state
	tcb.resetRcv(wnd, 0)
	tcb.resetSnd(iss, 1)
	tcb.pending = 0
	if state == StateSynSent {
		tcb.pending = FlagSYN
	}
	return nil
}

// Send processes a segment that is being sent to the network. It updates the TCB
// if there is no error.
func (tcb *ControlBlock) Send(seg Segment) error {
	err := tcb.validateOutgoingSegment(seg)
	if err != nil {
		return err
	}

	// The segment is valid, we can update TCB state.
	seglen := seg.LEN()
	tcb.snd.NXT.UpdateForward(seglen)
	tcb.rcv.WND = seg.WND
	hasFIN := seg.Flags.HasAny(FlagFIN)
	hasACK := seg.Flags.HasAny(FlagACK)
	switch tcb.state {
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
			tcb.pending = finack
		}
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
	default:
		err = errors.New("rcv: unexpected state " + tcb.state.String())
	}
	if err != nil {
		return err
	}

	tcb.pending = pending
	if prevNxt != 0 && tcb.snd.NXT != prevNxt {
		tcb.debuglog += fmt.Sprintf("rcv %s: snd.nxt changed from %x to %x on segment %+v\n", tcb.state, prevNxt, tcb.snd.NXT, seg)
	}

	// We accept the segment and update TCB state.
	tcb.snd.WND = seg.WND
	if seg.Flags.HasAny(FlagACK) {
		tcb.snd.UNA = seg.ACK
	}
	seglen := seg.LEN()
	tcb.rcv.NXT.UpdateForward(seglen)
	return err
}

// RecvNext returns the next sequence number expected to be received from remote.
// This implementation will reject segments that are not the next expected sequence.
// RecvNext returns 0 before StateSynRcvd.
func (tcb *ControlBlock) RecvNext() Value { return tcb.rcv.NXT }

// RecvWindow returns the receive window size as defined in the last call to Open. If connection is closed will return 0.
func (tcb *ControlBlock) RecvWindow() Size { return tcb.rcv.WND }

// ISS returns the initial sequence number of the connection that was defined on a call to Open by user.
func (tcb *ControlBlock) ISS() Value { return tcb.snd.ISS }

// MaxOutgoingSegmentSize returns the maximum size of a segment that can be sent by taking into account
// the send window size and the unacked data. Returns 0 before StateSynRcvd.
func (tcb *ControlBlock) MaxOutgoingSegmentSize() Size {
	if !tcb.hasIRS() {
		return 0 // SYN not yet received.
	}
	unacked := Sizeof(tcb.snd.UNA, tcb.snd.NXT)
	return tcb.snd.WND - unacked - 1 // TODO: is this -1 supposed to be here?
}

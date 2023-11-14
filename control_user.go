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
	return nil
}

// Recv processes a segment that is being received from the network. It updates the TCB
// if there is no error.
func (tcb *ControlBlock) Recv(seg Segment) (err error) {
	err = tcb.validateIncomingSegment(seg)
	if err != nil {
		if err == errDropSegment {
			return nil
		}
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

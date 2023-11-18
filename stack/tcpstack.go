package stack

import (
	"net/netip"
	"time"

	"github.com/soypat/seqs"
)

type tcp struct {
	stack     *PortStack
	scb       seqs.ControlBlock
	localPort uint16
	iss       seqs.Value
	wnd       seqs.Size
	lastTx    time.Time
	lastRx    time.Time
	// Remote fields discovered during an active open.
	remote    netip.AddrPort
	remoteMAC [6]byte
}

func (t *tcp) State() seqs.State {
	return t.scb.State()
}

// ListenTCP opens a passive TCP connection that listens on the given port.
func ListenTCP(stack *PortStack, port uint16, iss seqs.Value, window seqs.Size) (*tcp, error) {
	t := tcp{
		stack:     stack,
		localPort: port,
	}
	err := stack.OpenTCP(port, t.handleMain)
	if err != nil {
		return nil, err
	}
	err = t.scb.Open(iss, window, seqs.StateListen)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (t *tcp) handleMain(response []byte, pkt *TCPPacket) (n int, err error) {
	if t.mustSendSyn() {
		// Connection is still closed, we need to establish
		return t.handleInitSyn(response, pkt)
	}
	if pkt.HasPacket() {
		t.lastRx = pkt.Rx
		n, err := t.handleRecv(response, pkt)
		if n > 0 || err != nil {
			return n, err // Return early if something happened, else yield to user data handler.
		}
	}
	return t.handleUser(response, pkt)
}

func (t *tcp) handleRecv(response []byte, pkt *TCPPacket) (n int, err error) {
	// By this point we know that the packet is valid and contains data, we process it.
	payload := pkt.Payload()
	segIncoming := pkt.TCP.Segment(len(payload))
	// if segIncoming.SEQ != t.scb.RecvNext() {
	// 	return 0, ErrDroppedPacket // SCB does not admit out-of-order packets.
	// }
	err = t.scb.Recv(segIncoming)
	if err != nil {
		return 0, err
	}
	segOut, ok := t.scb.PendingSegment(0)
	if !ok {
		return 0, nil // Yield to handleUser.
	}
	pkt.InvertSrcDest()
	pkt.CalculateHeaders(segOut, nil)
	pkt.PutHeaders(response)
	return 54, t.scb.Send(segOut)
}

func (t *tcp) handleUser(response []byte, pkt *TCPPacket) (n int, err error) {

	return 0, nil
}

func (t *tcp) handleInitSyn(response []byte, pkt *TCPPacket) (n int, err error) {
	// Uninitialized TCB, we start the handshake.
	iss := t.iss
	wnd := t.wnd
	err = t.scb.Open(iss, wnd, seqs.StateSynSent)
	if err != nil {
		return 0, err
	}
	outSeg := seqs.Segment{
		SEQ:   iss,
		ACK:   0,
		Flags: seqs.FlagSYN,
		WND:   wnd,
	}
	copy(pkt.Eth.Source[:], t.stack.MAC)
	pkt.IP.Source = t.stack.IP.As4()
	pkt.TCP.SourcePort = t.localPort

	pkt.IP.Destination = t.remote.Addr().As4()
	pkt.TCP.DestinationPort = t.remote.Port()
	pkt.Eth.Destination = t.remoteMAC

	pkt.CalculateHeaders(outSeg, nil)
	pkt.PutHeaders(response)
	return 54, t.scb.Send(outSeg)
}

func (t *tcp) mustSendSyn() bool {
	return t.lastTx.IsZero() && t.scb.State() == seqs.StateClosed
}

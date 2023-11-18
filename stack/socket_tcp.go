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

// DialTCP opens an active TCP connection to the given remote address.
func DialTCP(stack *PortStack, localPort uint16, remoteMAC [6]byte, remote netip.AddrPort, iss seqs.Value, window seqs.Size) (*tcp, error) {
	t := tcp{
		stack:     stack,
		localPort: localPort,
		remote:    remote,
		remoteMAC: remoteMAC,
	}

	err := stack.OpenTCP(localPort, t.handleMain)
	if err != nil {
		return nil, err
	}
	err = t.scb.Open(iss, window, seqs.StateSynSent)
	if err != nil {
		return nil, err
	}
	err = t.scb.Send(t.synsentSegment())
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListenTCP opens a passive TCP connection that listens on the given port.
// ListenTCP only handles one connection at a time, so API may change in future to accomodate multiple connections.
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
	hasPacket := pkt.HasPacket()
	if !hasPacket && t.mustSendSyn() {
		// Connection is still closed, we need to establish
		return t.handleInitSyn(response, pkt)
	}

	if hasPacket {
		remotePort := t.remote.Port()
		if remotePort != 0 && pkt.TCP.SourcePort != remotePort {
			return 0, ErrDroppedPacket // This packet came from a different client to the one we are interacting with.
		}
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
		return 0, nil // No pending control segment. Yield to handleUser.
	}
	err = t.scb.Send(segOut)
	if err != nil {
		return 0, err
	}
	if segIncoming.Flags.HasAny(seqs.FlagSYN) && t.remote == (netip.AddrPort{}) {
		// We have a client that wants to connect to us.
		t.remote = netip.AddrPortFrom(netip.AddrFrom4(pkt.IP.Source), pkt.TCP.SourcePort)
	}
	pkt.InvertSrcDest()
	pkt.CalculateHeaders(segOut, nil)
	pkt.PutHeaders(response)
	return 54, nil
}

func (t *tcp) handleUser(response []byte, pkt *TCPPacket) (n int, err error) {
	return 0, nil
}

func (t *tcp) handleInitSyn(response []byte, pkt *TCPPacket) (n int, err error) {
	// Uninitialized TCB, we start the handshake.

	copy(pkt.Eth.Source[:], t.stack.MAC)
	pkt.IP.Source = t.stack.IP.As4()
	pkt.TCP.SourcePort = t.localPort

	pkt.IP.Destination = t.remote.Addr().As4()
	pkt.TCP.DestinationPort = t.remote.Port()
	pkt.Eth.Destination = t.remoteMAC

	pkt.CalculateHeaders(t.synsentSegment(), nil)
	pkt.PutHeaders(response)
	return 54, nil
}

func (t *tcp) awaitingSyn() bool {
	return t.scb.State() == seqs.StateSynSent && t.remote != (netip.AddrPort{})
}

func (t *tcp) mustSendSyn() bool {
	return t.awaitingSyn() && time.Since(t.lastTx) > 3*time.Second
}

func (t *tcp) close() {
	t.remote = netip.AddrPort{}
	t.wnd = 0
	t.iss = 0
	t.scb = seqs.ControlBlock{}
	t.lastTx = time.Time{}
	t.lastRx = time.Time{}
}

func (t *tcp) synsentSegment() seqs.Segment {
	return seqs.Segment{
		SEQ:   t.scb.ISS(),
		ACK:   0,
		Flags: seqs.FlagSYN,
		WND:   t.scb.RecvWindow(),
	}
}

package stack

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
)

const (
	defaultSocketSize = 2048
	sizeTCPNoOptions  = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
)

type TCPSocket struct {
	stack     *PortStack
	scb       seqs.ControlBlock
	localPort uint16
	lastTx    time.Time
	lastRx    time.Time
	// Remote fields discovered during an active open.
	remote    netip.AddrPort
	remoteMAC [6]byte
	tx        ring
	rx        ring
	abortErr  error
	closing   bool
}

func (t *TCPSocket) PortStack() *PortStack {
	return t.stack
}

func (t *TCPSocket) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(t.stack.Addr(), t.localPort)
}

func (t *TCPSocket) MAC() net.HardwareAddr {
	return t.stack.MAC()
}

func (t *TCPSocket) State() seqs.State {
	return t.scb.State()
}

func (t *TCPSocket) Send(b []byte) error {
	if t.abortErr != nil {
		return t.abortErr
	}
	if t.scb.State() != seqs.StateEstablished {
		return errors.New("connection not established")
	}
	if t.closing {
		return errors.New("connection closing")
	}
	if len(b) == 0 {
		return nil
	}
	if t.tx.buf == nil {
		t.tx = ring{
			buf: make([]byte, max(defaultSocketSize, len(b))),
		}
	}
	err := t.stack.FlagPendingTCP(t.localPort)
	if err != nil {
		return err
	}
	_, err = t.tx.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func (t *TCPSocket) Recv(b []byte) (int, error) {
	if t.abortErr != nil {
		return 0, t.abortErr
	}
	if t.closing {
		return 0, io.EOF
	}
	n, err := t.rx.Read(b)
	return n, err
}

// DialTCP opens an active TCP connection to the given remote address.
func DialTCP(stack *PortStack, localPort uint16, remoteMAC [6]byte, remote netip.AddrPort, iss seqs.Value, window seqs.Size) (*TCPSocket, error) {
	t := TCPSocket{
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
func ListenTCP(stack *PortStack, port uint16, iss seqs.Value, window seqs.Size) (*TCPSocket, error) {
	t := TCPSocket{
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

func (t *TCPSocket) Close() error {
	if t.abortErr != nil {
		return t.abortErr
	}
	toSend := t.tx.Buffered()
	if toSend == 0 {
		err := t.scb.Close()
		if err != nil {
			return err
		}
	}
	t.closing = true
	t.stack.FlagPendingTCP(t.localPort)
	return nil
}

func (t *TCPSocket) handleMain(response []byte, pkt *TCPPacket) (n int, err error) {
	if t.abortErr != nil {
		return 0, t.abortErr // Force close of socket.
	}
	defer func() {
		if err != nil && t.abortErr == nil && err != ErrFlagPending {
			err = nil // Only close socket if socket is aborted.
		} else if err != nil {
			t.stack.error("tcp socket", slog.Int("port", int(t.localPort)), slog.String("err", err.Error()))
		}
	}()
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
		err := t.handleRecv(pkt)
		if err != nil {
			return 0, err // Return early if something happened, else yield to user data handler.
		}
	}
	return t.handleSend(response, pkt)
}

func (t *TCPSocket) handleRecv(pkt *TCPPacket) (err error) {
	// By this point we know that the packet is valid and contains data, we process it.
	payload := pkt.Payload()
	segIncoming := pkt.TCP.Segment(len(payload))
	// if segIncoming.SEQ != t.scb.RecvNext() {
	// 	return 0, ErrDroppedPacket // SCB does not admit out-of-order packets.
	// }
	err = t.scb.Recv(segIncoming)
	if err != nil {
		return nil // Segment not admitted, yield to sender.
	}
	if segIncoming.Flags.HasAny(seqs.FlagPSH) {
		if len(payload) != int(segIncoming.DATALEN) {
			return errors.New("segment data length does not match payload length")
		}
		if t.rx.buf == nil {
			t.rx = ring{
				buf: make([]byte, defaultSocketSize),
			}
		}
		_, err = t.rx.Write(payload)
		if err != nil {
			return err
		}
	}
	if segIncoming.Flags.HasAny(seqs.FlagSYN) && t.remote == (netip.AddrPort{}) {
		// We have a client that wants to connect to us.
		t.remoteMAC = pkt.Eth.Source
		t.remote = netip.AddrPortFrom(netip.AddrFrom4(pkt.IP.Source), pkt.TCP.SourcePort)
	}
	return nil
}

func (t *TCPSocket) handleSend(response []byte, pkt *TCPPacket) (n int, err error) {
	available := min(t.tx.Buffered(), len(response)-sizeTCPNoOptions)
	seg, ok := t.scb.PendingSegment(available)
	if !ok && available == 0 {
		// No pending control segment or data to send. Yield to handleUser.
		return 0, errors.New("possible segment not found")
	}

	err = t.scb.Send(seg)
	if err != nil {
		return 0, err
	}

	// If we have user data to send we send it, else we send the control segment.
	var payload []byte
	if available > 0 {
		payload = response[sizeTCPNoOptions : sizeTCPNoOptions+seg.DATALEN]
		n, err = t.tx.Read(payload)
		if err != nil && err != io.EOF || n != int(seg.DATALEN) {
			panic("bug in handleUser") // This is a bug in ring buffer or a race condition.
		}
	}
	t.setSrcDest(pkt)
	pkt.CalculateHeaders(seg, payload)
	pkt.PutHeaders(response)

	if t.scb.HasPending() {
		err = ErrFlagPending // Flag to PortStack that we have pending data to send.
	} else if t.scb.State() == seqs.StateClosed {
		err = io.EOF
	}
	return sizeTCPNoOptions + n, err
}

func (t *TCPSocket) setSrcDest(pkt *TCPPacket) {
	pkt.Eth.Source = t.stack.MACAs6()
	pkt.IP.Source = t.stack.ip
	pkt.TCP.SourcePort = t.localPort

	pkt.IP.Destination = t.remote.Addr().As4()
	pkt.TCP.DestinationPort = t.remote.Port()
	pkt.Eth.Destination = t.remoteMAC
}

func (t *TCPSocket) handleInitSyn(response []byte, pkt *TCPPacket) (n int, err error) {
	// Uninitialized TCB, we start the handshake.
	t.setSrcDest(pkt)
	pkt.CalculateHeaders(t.synsentSegment(), nil)
	pkt.PutHeaders(response)
	return sizeTCPNoOptions, nil
}

func (t *TCPSocket) awaitingSyn() bool {
	return t.scb.State() == seqs.StateSynSent && t.remote != (netip.AddrPort{})
}

func (t *TCPSocket) mustSendSyn() bool {
	return t.awaitingSyn() && time.Since(t.lastTx) > 3*time.Second
}

func (t *TCPSocket) close() {
	t.remote = netip.AddrPort{}
	t.scb = seqs.ControlBlock{}
	t.lastTx = time.Time{}
	t.lastRx = time.Time{}
	t.closing = false
	// t.stack.CloseTCP(t.localPort)
	t.abortErr = io.ErrClosedPipe
}

func (t *TCPSocket) synsentSegment() seqs.Segment {
	return seqs.Segment{
		SEQ:   t.scb.ISS(),
		ACK:   0,
		Flags: seqs.FlagSYN,
		WND:   t.scb.RecvWindow(),
	}
}

func (t *TCPSocket) abort(err error) error {
	t.close()
	t.abortErr = err
	return err
}

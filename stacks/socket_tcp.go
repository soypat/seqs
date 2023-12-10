package stacks

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
)

var _ itcphandler = (*TCPSocket)(nil)

const (
	defaultSocketSize = 2048
	sizeTCPNoOptions  = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
)

type TCPSocket struct {
	stack     *PortStack
	scb       seqs.ControlBlock
	pkt       TCPPacket
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

type TCPSocketConfig struct {
	TxBufSize int
	RxBufSize int
}

func NewTCPSocket(stack *PortStack, cfg TCPSocketConfig) (*TCPSocket, error) {
	if cfg.RxBufSize == 0 {
		cfg.RxBufSize = defaultSocketSize
	}
	if cfg.TxBufSize == 0 {
		cfg.TxBufSize = defaultSocketSize
	}
	sock := &TCPSocket{
		stack: stack,
		tx:    ring{buf: make([]byte, cfg.TxBufSize)},
		rx:    ring{buf: make([]byte, cfg.RxBufSize)},
	}
	return sock, nil
}
func (sock *TCPSocket) PortStack() *PortStack {
	return sock.stack
}

func (sock *TCPSocket) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(sock.stack.Addr(), sock.localPort)
}

func (sock *TCPSocket) MAC() net.HardwareAddr {
	return sock.stack.MAC()
}

func (sock *TCPSocket) State() seqs.State {
	state := sock.scb.State()
	if sock.closing && !state.IsClosing() {
		// User already called close but SCB still did not receive close call.
		state = seqs.StateFinWait1
	}
	return state
}

func (sock *TCPSocket) FlushOutputBuffer() error {
	i := 0
	for sock.tx.Buffered() > 0 {
		sleep := time.Nanosecond << i
		time.Sleep(sleep)
		if sleep < time.Second {
			i++
		}
	}
	return nil
}

// Write writes argument data to the socket's output buffer which is queued to be sent.
func (sock *TCPSocket) Write(b []byte) (int, error) {
	if sock.abortErr != nil {
		return 0, sock.abortErr
	}
	state := sock.State()
	if state.IsClosing() || state.IsClosed() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	err := sock.stack.FlagPendingTCP(sock.localPort)
	if err != nil {
		return 0, err
	}
	n, err := sock.tx.Write(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Read reads data from the socket's input buffer. If the buffer is empty,
// Read will block until data is available.
func (sock *TCPSocket) Read(b []byte) (int, error) {
	return sock.ReadDeadline(b, time.Time{})
}

// BufferedInput returns the number of bytes in the socket's input buffer.
func (sock *TCPSocket) BufferedInput() int { return sock.rx.Buffered() }

// Read reads data from the socket's input buffer. If the buffer is empty
// it will wait until the deadline is met or data is available.
func (sock *TCPSocket) ReadDeadline(b []byte, deadline time.Time) (int, error) {
	if sock.abortErr != nil {
		return 0, sock.abortErr
	}
	state := sock.State()
	if state.IsClosed() || state.IsClosing() {
		return 0, net.ErrClosed
	}
	noDeadline := deadline.IsZero()
	for sock.rx.Buffered() == 0 && sock.State() == seqs.StateEstablished && (noDeadline || time.Until(deadline) > 0) {
		runtime.Gosched()
	}
	n, err := sock.rx.Read(b)
	return n, err
}

// OpenDialTCP opens an active TCP connection to the given remote address.
func (sock *TCPSocket) OpenDialTCP(localPort uint16, remoteMAC [6]byte, remote netip.AddrPort, iss seqs.Value) error {
	return sock.open(seqs.StateSynSent, localPort, iss, remoteMAC, remote)
}

// OpenListenTCP opens a passive TCP connection that listens on the given port.
// OpenListenTCP only handles one connection at a time, so API may change in future to accomodate multiple connections.
func (sock *TCPSocket) OpenListenTCP(localPortNum uint16, iss seqs.Value) error {
	return sock.open(seqs.StateListen, localPortNum, iss, [6]byte{}, netip.AddrPort{})
}

func (sock *TCPSocket) open(state seqs.State, localPortNum uint16, iss seqs.Value, remoteMAC [6]byte, remoteAddr netip.AddrPort) error {
	err := sock.scb.Open(iss, seqs.Size(len(sock.rx.buf)), seqs.StateSynSent)
	if err != nil {
		return err
	}
	sock.remoteMAC = remoteMAC
	sock.remote = remoteAddr
	sock.localPort = localPortNum
	sock.rx.Reset()
	sock.tx.Reset()
	err = sock.stack.OpenTCP(localPortNum, sock)
	if err != nil {
		return err
	}
	if state == seqs.StateSynSent {
		err = sock.stack.FlagPendingTCP(localPortNum)
		if err != nil {
			sock.stack.CloseTCP(localPortNum)
			return err
		}
		err = sock.scb.Send(sock.synsentSegment())
	}
	return err
}

func (sock *TCPSocket) Close() error {
	toSend := sock.tx.Buffered()
	if toSend == 0 {
		err := sock.scb.Close()
		if err != nil {
			return err
		}
	}
	sock.closing = true
	sock.stack.FlagPendingTCP(sock.localPort)
	return nil
}

func (sock *TCPSocket) isPendingHandling() bool {
	return sock.mustSendSyn() || sock.scb.HasPending() || sock.tx.Buffered() > 0 || sock.closing
}

func (sock *TCPSocket) recv(pkt *TCPPacket) (err error) {
	prevState := sock.scb.State()
	if prevState.IsClosed() {
		return io.EOF
	}

	remotePort := sock.remote.Port()
	if remotePort != 0 && pkt.TCP.SourcePort != remotePort {
		return nil // This packet came from a different client to the one we are interacting with.
	}
	sock.lastRx = pkt.Rx
	// By this point we know that the packet is valid and contains data, we process it.
	payload := pkt.Payload()
	segIncoming := pkt.TCP.Segment(len(payload))

	err = sock.scb.Recv(segIncoming)
	if err != nil {
		return nil // Segment not admitted, yield to sender.
	}
	if prevState != sock.scb.State() {
		sock.stack.info("TCP:rx-statechange", slog.Uint64("port", uint64(sock.localPort)), slog.String("old", prevState.String()), slog.String("new", sock.scb.State().String()), slog.String("rxflags", segIncoming.Flags.String()))
	}
	if segIncoming.Flags.HasAny(seqs.FlagPSH) {
		if len(payload) != int(segIncoming.DATALEN) {
			return errors.New("segment data length does not match payload length")
		}
		_, err = sock.rx.Write(payload)
		if err != nil {
			return err
		}
	}
	if segIncoming.Flags.HasAny(seqs.FlagSYN) && !sock.remote.IsValid() {
		// We have a client that wants to connect to us.
		sock.remoteMAC = pkt.Eth.Source
		sock.remote = netip.AddrPortFrom(netip.AddrFrom4(pkt.IP.Source), pkt.TCP.SourcePort)
	}
	err = sock.stateCheck()
	return err
}

func (sock *TCPSocket) send(response []byte) (n int, err error) {
	if !sock.remote.IsValid() {
		return 0, nil // No remote address yet, yield.
	}
	if sock.mustSendSyn() {
		// Connection is still closed, we need to establish
		return sock.handleInitSyn(response)
	}
	available := min(sock.tx.Buffered(), len(response)-sizeTCPNoOptions)
	seg, ok := sock.scb.PendingSegment(available)
	if !ok {
		// No pending control segment or data to send. Yield to handleUser.
		return 0, nil
	}

	prevState := sock.scb.State()
	err = sock.scb.Send(seg)
	if err != nil {
		return 0, err
	}

	// If we have user data to send we send it, else we send the control segment.
	var payload []byte
	if available > 0 {
		payload = response[sizeTCPNoOptions : sizeTCPNoOptions+seg.DATALEN]
		n, err = sock.tx.Read(payload)
		if err != nil && err != io.EOF || n != int(seg.DATALEN) {
			panic("bug in handleUser") // This is a bug in ring buffer or a race condition.
		}
	}
	sock.setSrcDest(&sock.pkt)
	sock.pkt.CalculateHeaders(seg, payload)
	sock.pkt.PutHeaders(response)
	if prevState != sock.scb.State() {
		sock.stack.info("TCP:tx-statechange", slog.Uint64("port", uint64(sock.localPort)), slog.String("old", prevState.String()), slog.String("new", sock.scb.State().String()), slog.String("txflags", seg.Flags.String()))
	}
	err = sock.stateCheck()
	return sizeTCPNoOptions + n, err
}

func (sock *TCPSocket) setSrcDest(pkt *TCPPacket) {
	pkt.Eth.Source = sock.stack.MACAs6()
	pkt.IP.Source = sock.stack.ip
	pkt.TCP.SourcePort = sock.localPort

	pkt.IP.Destination = sock.remote.Addr().As4()
	pkt.TCP.DestinationPort = sock.remote.Port()
	pkt.Eth.Destination = sock.remoteMAC
}

func (sock *TCPSocket) handleInitSyn(response []byte) (n int, err error) {
	// Uninitialized TCB, we start the handshake.
	sock.setSrcDest(&sock.pkt)
	sock.pkt.CalculateHeaders(sock.synsentSegment(), nil)
	sock.pkt.PutHeaders(response)
	return sizeTCPNoOptions, nil
}

func (sock *TCPSocket) awaitingSyn() bool {
	return sock.scb.State() == seqs.StateSynSent && sock.remote != (netip.AddrPort{})
}

func (sock *TCPSocket) mustSendSyn() bool {
	return sock.awaitingSyn() && time.Since(sock.lastTx) > 3*time.Second
}

func (sock *TCPSocket) deleteState() {
	*sock = TCPSocket{
		stack: sock.stack,
		rx:    ring{buf: sock.rx.buf},
		tx:    ring{buf: sock.tx.buf},
	}
}

func (sock *TCPSocket) synsentSegment() seqs.Segment {
	return seqs.Segment{
		SEQ:   sock.scb.ISS(),
		ACK:   0,
		Flags: seqs.FlagSYN,
		WND:   sock.scb.RecvWindow(),
	}
}

func (sock *TCPSocket) stateCheck() (portStackErr error) {
	state := sock.State()
	txEmpty := sock.tx.Buffered() == 0
	// Close checks:
	if sock.closing && txEmpty && sock.scb.State() == seqs.StateEstablished { // Get RAW state of SCB.
		sock.scb.Close()
		sock.stack.debug("TCP:delayed-close", slog.Uint64("port", uint64(sock.localPort)))
	}
	if sock.scb.HasPending() {
		portStackErr = ErrFlagPending // Flag to PortStack that we have pending data to send.
	} else if state.IsClosed() {
		portStackErr = io.EOF // On EOF portStack will abort the connection.
	}
	return portStackErr
}

// abort is called by the PortStack when the port is closed. This happens
// on EOF returned by Handle/RecvEth. See TCPSocket.stateCheck for information on when
// a connection is aborted.
func (t *TCPSocket) abort() {
	t.deleteState()
}

package stacks

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/internal"
)

var _ net.Conn = &TCPConn{}

var _ itcphandler = (*TCPConn)(nil)

const (
	defaultSocketSize = 2048
	sizeTCPNoOptions  = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
)

// TCPConn is a userspace implementation of a TCP connection intended for use with PortStack
// though is purposefully loosely coupled. It implements [net.Conn].
type TCPConn struct {
	stack  *PortStack
	rdead  time.Time
	wdead  time.Time
	lastTx time.Time
	lastRx time.Time
	pkt    TCPPacket
	scb    seqs.ControlBlock
	tx     ring
	rx     ring
	// remote is the IP+port address of remote.
	remote    netip.AddrPort
	localPort uint16
	remoteMAC [6]byte
	abortErr  error
	closing   bool
	// connid is a conenction counter that is incremented each time a new
	// connection is established via Open calls. This disambiguate's whether
	// Read and Write calls belong to the current connection.
	connid uint8
	// Avoid heap allocations by making LocalAddr and RemoteAddr give out pointers to these fields.
	raddr, laddr net.TCPAddr
}

type TCPConnConfig struct {
	TxBufSize uint16
	RxBufSize uint16
}

func NewTCPConn(stack *PortStack, cfg TCPConnConfig) (*TCPConn, error) {
	if cfg.RxBufSize == 0 {
		cfg.RxBufSize = defaultSocketSize
	}
	if cfg.TxBufSize == 0 {
		cfg.TxBufSize = defaultSocketSize
	}
	buf := make([]byte, cfg.RxBufSize+cfg.TxBufSize)
	sock := makeTCPConn(stack, buf[:cfg.TxBufSize], buf[cfg.TxBufSize:cfg.TxBufSize+cfg.RxBufSize])
	sock.trace("NewTCPConn:end")
	return &sock, nil
}

func makeTCPConn(stack *PortStack, tx, rx []byte) TCPConn {
	return TCPConn{
		stack: stack,
		tx:    ring{buf: tx},
		rx:    ring{buf: rx},
	}
}

// PortStack returns the PortStack that this socket is attached to.
func (sock *TCPConn) PortStack() *PortStack {
	return sock.stack
}

// LocalPort returns the local port on which the socket is listening or connected to.
func (sock *TCPConn) LocalPort() uint16 { return sock.localPort }

// State returns the TCP state of the socket.
func (sock *TCPConn) State() seqs.State {
	state := sock.scb.State()
	if sock.closing && !state.IsClosing() {
		// User already called close but SCB still did not receive close call.
		state = seqs.StateFinWait1
	}
	return state
}

// FlushOutputBuffer waits until the output buffer is empty or the socket is closed.
func (sock *TCPConn) FlushOutputBuffer() error {
	sock.trace("TCPConn.FlushOutputBuffer:start")
	if sock.State().IsClosed() {
		return net.ErrClosed
	}
	i := 0
	for sock.tx.Buffered() > 0 && !sock.State().IsClosed() {
		sleep := time.Nanosecond << i
		time.Sleep(sleep)
		if sleep < time.Second {
			i++
		}
	}
	return nil
}

// Write writes argument data to the socket's output buffer which is queued to be sent.
func (sock *TCPConn) Write(b []byte) (n int, _ error) {
	err := sock.checkPipeOpen()
	if err != nil {
		return 0, err
	}
	sock.trace("TCPConn.Write:start")
	connid := sock.connid
	if sock.deadlineExceeded(sock.wdead) {
		return 0, os.ErrDeadlineExceeded
	}
	if len(b) == 0 {
		return 0, nil
	}
	err = sock.stack.FlagPendingTCP(sock.localPort)
	if err != nil {
		return 0, err
	}
	plen := len(b)
	backoff := internal.NewBackoff(internal.BackoffHasPriority)
	for {
		if sock.abortErr != nil {
			return n, sock.abortErr
		} else if connid != sock.connid {
			return n, net.ErrClosed
		}
		ngot, _ := sock.tx.Write(b)
		n += ngot
		b = b[ngot:]
		if n == plen {
			return n, nil
		} else if ngot > 0 {
			backoff.Hit()
			runtime.Gosched()
		} else {
			backoff.Miss()
		}

		sock.trace("TCPConn.Write:insuf-buf", slog.Int("missing", plen-n))
		if sock.deadlineExceeded(sock.wdead) {
			return n, os.ErrDeadlineExceeded
		}
		err = sock.stack.FlagPendingTCP(sock.localPort)
		if err != nil {
			return n, err
		}
	}
}

// Read reads data from the socket's input buffer. If the buffer is empty,
// Read will block until data is available.
func (sock *TCPConn) Read(b []byte) (int, error) {
	err := sock.checkPipeOpen()
	if err != nil {
		return 0, err
	}
	sock.trace("TCPConn.Read:start")
	connid := sock.connid
	backoff := internal.NewBackoff(internal.BackoffHasPriority)
	for sock.rx.Buffered() == 0 && sock.State() == seqs.StateEstablished {
		if sock.abortErr != nil {
			return 0, sock.abortErr
		} else if connid != sock.connid {
			return 0, net.ErrClosed
		}
		if sock.deadlineExceeded(sock.rdead) {
			return 0, os.ErrDeadlineExceeded
		}
		backoff.Miss()
	}
	n, err := sock.rx.Read(b)
	return n, err
}

// BufferedInput returns the number of bytes in the socket's input buffer.
func (sock *TCPConn) BufferedInput() int { return sock.rx.Buffered() }

// LocalAddr implements [net.Conn] interface.
func (sock *TCPConn) LocalAddr() net.Addr {
	sock.laddr = net.TCPAddr{
		IP:   sock.stack.ip[:],
		Port: int(sock.localPort),
	}
	return &sock.laddr
}

// RemoteAddr implements [net.Conn] interface.
func (sock *TCPConn) RemoteAddr() net.Addr {
	sock.raddr = net.TCPAddr{
		IP:   sock.remote.Addr().AsSlice(),
		Port: int(sock.remote.Port()),
	}
	return &sock.raddr
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline. Implements [net.Conn].
func (sock *TCPConn) SetDeadline(t time.Time) error {
	err := sock.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return sock.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call. A zero value for t means Read will not time out.
func (sock *TCPConn) SetReadDeadline(t time.Time) error {
	sock.trace("TCPConn.SetReadDeadline:start")
	err := sock.checkPipeOpen()
	if err == nil {
		sock.rdead = t
	}
	return err
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (sock *TCPConn) SetWriteDeadline(t time.Time) error {
	sock.trace("TCPConn.SetWriteDeadline:start")
	err := sock.checkPipeOpen()
	if err == nil {
		sock.wdead = t
	}
	return err
}

func (sock *TCPConn) deadlineExceeded(dead time.Time) bool {
	return !dead.IsZero() && time.Since(dead) > 0
}

// OpenDialTCP opens an active TCP connection to the given remote address.
func (sock *TCPConn) OpenDialTCP(localPort uint16, remoteMAC [6]byte, remote netip.AddrPort, iss seqs.Value) error {
	sock.trace("TCPConn.OpenDialTCP:start")
	return sock.openstack(seqs.StateSynSent, localPort, iss, remoteMAC, remote)
}

// OpenListenTCP opens a passive TCP connection that listens on the given port.
// OpenListenTCP only handles one connection at a time, so API may change in future to accomodate multiple connections.
func (sock *TCPConn) OpenListenTCP(localPortNum uint16, iss seqs.Value) error {
	sock.trace("TCPConn.OpenListenTCP:start")
	return sock.openstack(seqs.StateListen, localPortNum, iss, [6]byte{}, netip.AddrPort{})
}

func (sock *TCPConn) openstack(state seqs.State, localPortNum uint16, iss seqs.Value, remoteMAC [6]byte, remoteAddr netip.AddrPort) error {
	err := sock.stack.OpenTCP(localPortNum, sock)
	if err != nil {
		return err
	}
	if state == seqs.StateSynSent {
		err = sock.stack.FlagPendingTCP(localPortNum)
		if err != nil {
			sock.stack.CloseTCP(localPortNum)
			return err
		}
	}
	err = sock.open(state, localPortNum, iss, remoteMAC, remoteAddr)
	if err != nil {
		sock.stack.CloseTCP(localPortNum)
	}
	return err
}

func (sock *TCPConn) open(state seqs.State, localPortNum uint16, iss seqs.Value, remoteMAC [6]byte, remoteAddr netip.AddrPort) error {
	err := sock.scb.Open(iss, seqs.Size(len(sock.rx.buf)), state)
	if err != nil {
		return err
	}
	sock.scb.SetLogger(sock.stack.logger)
	sock.remoteMAC = remoteMAC
	sock.remote = remoteAddr
	sock.localPort = localPortNum
	sock.rx.Reset()
	sock.tx.Reset()
	if state == seqs.StateSynSent {
		err = sock.scb.Send(sock.synsentSegment())
	}
	if err == nil {
		sock.connid++
	}
	return err
}

func (sock *TCPConn) Close() error {
	toSend := sock.tx.Buffered()
	if toSend == 0 {
		err := sock.scb.Close()
		if err != nil {
			if sock.scb.State().IsClosing() {
				// TODO(soypat): FinWait2 and Timewait would prevent socket from closing indefinetely if it were not for this.
				sock.closing = true
			}
			return err
		}
	}
	sock.closing = true
	sock.stack.FlagPendingTCP(sock.localPort)
	return nil
}

func (sock *TCPConn) isPendingHandling() bool {
	return sock.scb.HasPending() || sock.mustSendSyn() || sock.tx.Buffered() > 0 || sock.closing
}

// checkPipeOpen checks if user data can be sent over the socket.
func (sock *TCPConn) checkPipeOpen() error {
	if sock.abortErr != nil {
		return sock.abortErr
	}
	state := sock.State()
	if sock.closing || state.IsClosed() || state.IsClosing() {
		return net.ErrClosed
	}
	return nil
}

func (sock *TCPConn) recv(pkt *TCPPacket) (err error) {
	sock.trace("TCPConn.recv:start")
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
	if sock.scb.IncomingIsKeepalive(segIncoming) {
		sock.trace("TCPConn.recv:keepalive")
		return nil
	}
	err = sock.scb.Recv(segIncoming)
	if err != nil {
		if sock.scb.State() == seqs.StateClosed {
			sock.info("TCP:rx-abort")
			sock.abortErr = err
			return io.EOF // Connection closed by reset.
		}
		return nil // Segment not admitted, yield to sender.
	}
	if prevState != sock.scb.State() {
		sock.info("TCP:rx-statechange", slog.Uint64("port", uint64(sock.localPort)), slog.String("old", prevState.String()), slog.String("new", sock.scb.State().String()), slog.String("rxflags", segIncoming.Flags.String()))
	}
	if segIncoming.DATALEN > 0 {
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

func (sock *TCPConn) send(response []byte) (n int, err error) {
	defer sock.trace("TCPConn.send:start")
	if !sock.remote.IsValid() {
		return 0, nil // No remote address yet, yield.
	}
	if sock.awaitingSyn() {
		// Connection is still preestablished, we need to establish
		if sock.mustSendSyn() {
			return sock.handleInitSyn(response)
		}
		// We sent the initializing SYN less than N seconds ago, yield.
		return 0, ErrFlagPending
	}

	// Advertise our receive window as the amount of space available in our receive buffer.
	sock.scb.SetRecvWindow(seqs.Size(sock.rx.Free()))

	available := min(sock.tx.Buffered(), len(response)-sizeTCPNoOptions)
	seg, ok := sock.scb.PendingSegment(available)
	if !ok {
		// No pending control segment or data to send. Yield to handleUser.
		return 0, sock.stateCheck()
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
		sock.info("TCP:tx-statechange", slog.Uint64("port", uint64(sock.localPort)), slog.String("old", prevState.String()), slog.String("new", sock.scb.State().String()), slog.String("txflags", seg.Flags.String()))
	}
	err = sock.stateCheck()
	sock.onsend(response[:sizeTCPNoOptions+n])
	return sizeTCPNoOptions + n, err
}

func (sock *TCPConn) setSrcDest(pkt *TCPPacket) {
	pkt.Eth.Source = sock.stack.HardwareAddr6()
	pkt.IP.Source = sock.stack.ip
	pkt.TCP.SourcePort = sock.localPort

	pkt.IP.Destination = sock.remote.Addr().As4()
	pkt.TCP.DestinationPort = sock.remote.Port()
	pkt.Eth.Destination = sock.remoteMAC
}

func (sock *TCPConn) handleInitSyn(response []byte) (n int, err error) {
	// Uninitialized TCB, we start the handshake.
	sock.setSrcDest(&sock.pkt)
	sock.pkt.CalculateHeaders(sock.synsentSegment(), nil)
	sock.pkt.PutHeaders(response)
	sock.onsend(response[:sizeTCPNoOptions])
	return sizeTCPNoOptions, nil
}

func (sock *TCPConn) awaitingSyn() bool {
	return sock.scb.State() == seqs.StateSynSent && sock.remote != (netip.AddrPort{})
}

func (sock *TCPConn) mustSendSyn() bool {
	// lastTx is zero-valued on init, so this will trigger on t=0 and every 3 seconds.
	return sock.awaitingSyn() && time.Since(sock.lastTx) > 3*time.Second
}

func (sock *TCPConn) onsend(b []byte) {
	if len(b) > 0 {
		sock.lastTx = sock.stack.now()
	}
}

func (sock *TCPConn) deleteState() {
	sock.trace("TCPConn.deleteState", slog.Uint64("port", uint64(sock.localPort)))
	*sock = TCPConn{
		stack:  sock.stack,
		rx:     ring{buf: sock.rx.buf},
		tx:     ring{buf: sock.tx.buf},
		connid: sock.connid + 1,
	}
}

func (sock *TCPConn) synsentSegment() seqs.Segment {
	return seqs.Segment{
		SEQ:   sock.scb.ISS(),
		ACK:   0,
		Flags: seqs.FlagSYN,
		WND:   sock.scb.RecvWindow(),
	}
}

func (sock *TCPConn) stateCheck() (portStackErr error) {
	state := sock.State()
	txEmpty := sock.tx.Buffered() == 0
	// Close checks:
	if sock.closing {
		if txEmpty && sock.scb.State() == seqs.StateEstablished { // Get RAW state of SCB.
			sock.scb.Close()
			sock.debug("TCP:delayed-close", slog.Uint64("port", uint64(sock.localPort)))
		} else {
			now := sock.stack.now()
			elapsed := now.Sub(sock.lastTx)
			if elapsed > 3*time.Second {
				sock.logerr("TCP:idleabort", slog.Duration("elapsed", elapsed))
				return io.EOF // Abort connection- no response from remote.
			}
		}
	}

	if sock.scb.HasPending() {
		sock.trace("TCPConn.stateCheck:hasPending")
		portStackErr = ErrFlagPending // Flag to PortStack that we have pending data to send.
	} else if state.IsClosed() {
		sock.trace("TCPConn.stateCheck:closed")
		portStackErr = io.EOF // On EOF portStack will abort the connection.
	}
	return portStackErr
}

// abort is called by the PortStack when the port is closed. This happens
// on EOF returned by Handle/RecvEth. See TCPSocket.stateCheck for information on when
// a connection is aborted.
func (sock *TCPConn) abort() {
	sock.deleteState()
}

func (sock *TCPConn) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(sock.stack.logger, internal.LevelTrace, msg, attrs...)
}

func (sock *TCPConn) debug(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(sock.stack.logger, slog.LevelDebug, msg, attrs...)
}

func (sock *TCPConn) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(sock.stack.logger, slog.LevelInfo, msg, attrs...)
}

func (sock *TCPConn) logerr(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(sock.stack.logger, slog.LevelError, msg, attrs...)
}

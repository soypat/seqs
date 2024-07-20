package stacks

//UDP is 'connectionless' so this is only a connection in so far as it's a bunch of packets arriving on a common port
//Packets can fail to arrive, or arrive out of order, or arrive more than once - this is the nature of UDP
//It is very easy to build a reliable protocol on top of UDP

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/internal"
)

var _ net.Conn = &UDPConn{} //net.conn is part of the standard go library - it's an interface we must implement

// The handler is a set of methods (primarily send and recv) that the underlying port stack will call, to pass packets for processing
// it is an interface we need to implement
var _ iudphandler = (*UDPConn)(nil)

var defaultUDPbuffSize = uint16(4096) //a bit arbitrary

const (
	//defaultSocketSize = 2048
	sizeUDPNoOptions = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
)

type UDPConn struct {
	stack        *PortStack
	lastRx       time.Time
	pkt          UDPPacket //this is a reusable 'scratchpad' packet used for sending
	tx           ring      //the ring buffers contain unpacketised data
	rx           ring
	remote       netip.AddrPort
	localPort    uint16
	remoteMAC    [6]byte //this is a local peer - OR the ROUTER/Gateways mac address
	raddr, laddr net.UDPAddr
	// Read and Write deadlines.
	rdeadline, wdeadline time.Time
	connid               uint8
	closing              bool
}

// this is an identical structure to TCPConnConfig - but I didn't want to change the original name without discussions
type UDPConnConfig struct {
	TxBufSize uint16
	RxBufSize uint16
}

func NewUDPConn(stack *PortStack, cfg UDPConnConfig) (*UDPConn, error) {

	if cfg.RxBufSize == 0 {
		cfg.RxBufSize = defaultUDPbuffSize
	}
	if cfg.TxBufSize == 0 {
		cfg.TxBufSize = defaultUDPbuffSize
	}

	tx, rx := contiguous2Bufs(int(cfg.TxBufSize), int(cfg.RxBufSize))
	sock := makeUDPConn(stack, tx, rx)
	sock.trace("NewUDPConn:end")
	return &sock, nil

}

func makeUDPConn(stack *PortStack, tx, rx []byte) UDPConn {
	return UDPConn{
		stack: stack,
		tx:    ring{buf: tx},
		rx:    ring{buf: rx},
	}
}

// OpenDialUDP won't really do anything - other than choose a local outbound port) ???
func (sock *UDPConn) OpenDialUDP(localPort uint16, remoteMAC [6]byte, remote netip.AddrPort) error {
	if !remote.IsValid() {
		return errors.New("invalid netip.AddrPort")
	}
	sock.trace("UDPConn.OpenDialUDP:start")
	err := sock.stack.OpenUDP(localPort, sock)
	if err != nil {
		return err
	}
	sock.closing = false
	sock.connid++
	sock.remoteMAC = remoteMAC //this is our router/gateway MAC address - we never get to know the remote MAC address (that would be a security issue)
	sock.remote = remote
	sock.localPort = localPort
	sock.rx.Reset()
	sock.tx.Reset()
	return nil
}

// abort deletes connection state and fails all pending Read/Write calls.
func (sock *UDPConn) abort() {
	sock.rx.Reset()
	sock.tx.Reset()
	*sock = UDPConn{
		stack:  sock.stack,
		tx:     sock.tx,
		rx:     sock.tx,
		connid: sock.connid + 1,
	}
}

func (sock *UDPConn) isPendingHandling() bool {
	// much simpler than TCP - may need expanding??
	return sock.closing || sock.tx.Buffered() > 0
}

// Read reads from the underlying RX ring buffer, throws an EOF error if no data is available
func (sock *UDPConn) Read(b []byte) (int, error) {
	err := sock.checkPipeClosed()
	if err != nil {
		return 0, err
	}
	connid := sock.connid
	backoff := internal.NewBackoff(internal.BackoffHasPriority)
	for sock.rx.Buffered() == 0 {
		if connid != sock.connid {
			return 0, net.ErrClosed
		} else if !sock.wdeadline.IsZero() && time.Since(sock.wdeadline) > 0 {
			return 0, os.ErrDeadlineExceeded
		}
		backoff.Miss()
	}
	return sock.rx.Read(b) //read from the rx ring buffer into b
}

func (sock *UDPConn) BufferedInput() int {
	if sock.closing || sock.localPort == 0 {
		return 0
	}
	return sock.rx.Buffered()
}

func (sock *UDPConn) FlushOutputBuffer() error {
	sock.trace("UDPConn.FlushOutputBuffer:start")
	if err := sock.checkPipeClosed(); err != nil {
		return err
	}
	backoff := internal.NewBackoff(internal.BackoffHasPriority)
	connid := sock.connid
	for sock.tx.Buffered() > 0 {
		backoff.Miss()
		if connid != sock.connid {
			return net.ErrClosed
		}
	}
	return nil
}

// Write writes into the underlying tx ring buffer - calls to the portStacks [PortStack.PutOutboundEth] will send the (queued) data
func (sock *UDPConn) Write(b []byte) (int, error) {
	err := sock.checkPipeClosed()
	if err != nil {
		return 0, err
	}
	err = sock.stack.FlagPendingUDP(sock.localPort)
	if err != nil {
		return 0, err
	}
	connid := sock.connid
	totalLen := len(b)
	backoff := internal.NewBackoff(internal.BackoffHasPriority)

	for {
		if connid != sock.connid {
			// Important check before writing to buffer- maybe connection was aborted during sleep.
			return totalLen - len(b), net.ErrClosed
		}
		n, _ := sock.tx.Write(b)
		b = b[n:]
		if len(b) == 0 {
			break
		}
		if n == 0 && !sock.wdeadline.IsZero() && time.Since(sock.wdeadline) > 0 {
			return totalLen - len(b), os.ErrDeadlineExceeded
		} else if n == 0 {
			backoff.Miss()
		} else {
			backoff.Hit()
			runtime.Gosched()
		}
		err = sock.stack.FlagPendingUDP(sock.localPort)
		if err != nil {
			return totalLen - len(b), err
		}
	}
	return totalLen, nil
}

func (sock *UDPConn) Close() error {
	if sock.localPort == 0 {
		return net.ErrClosed
	}
	sock.closing = true
	sock.stack.FlagPendingUDP(sock.localPort)
	return nil
}

func (sock *UDPConn) checkPipeClosed() error {
	if sock.closing {
		return io.EOF
	} else if sock.localPort == 0 {
		return net.ErrClosed
	}
	return nil
}

func (sock *UDPConn) LocalAddr() net.Addr {
	sock.laddr = net.UDPAddr{
		IP:   sock.stack.ip[:],
		Port: int(sock.localPort),
	}
	return &sock.laddr
}

func (sock *UDPConn) RemoteAddr() net.Addr {
	sock.raddr = net.UDPAddr{
		IP:   sock.remote.Addr().AsSlice(),
		Port: int(sock.remote.Port()),
	}
	return &sock.raddr
}

func (sock *UDPConn) SetDeadline(t time.Time) error {
	sock.SetReadDeadline(t)
	sock.SetWriteDeadline(t)
	return nil
}

func (sock *UDPConn) SetReadDeadline(t time.Time) error {
	sock.rdeadline = t
	return nil
}

func (sock *UDPConn) SetWriteDeadline(t time.Time) error {
	sock.wdeadline = t
	return nil
}

// recvEth implements the [iudphandler] interface.
func (sock *UDPConn) recvEth(pkt *UDPPacket) (err error) {
	sock.trace("UDP.recv:start")
	if sock.closing {
		return io.EOF
	}

	remotePort := sock.remote.Port()
	if remotePort != 0 && pkt.UDP.SourcePort != remotePort {
		return nil // This packet came from a different client (remote port) to the one we are interacting with.
	}
	sock.lastRx = pkt.Rx
	// By this point we know that the packet is valid and contains data, we process it.
	payload := pkt.Payload()
	_, err = sock.rx.Write(payload) //write into the UDPconns rx (ring) buffer

	return err //which is hopefully nil - but could be errRingBufferFull
}

// putOutboundEth implements the [iudphandler] interface.
func (sock *UDPConn) putOutboundEth(response []byte) (n int, err error) {
	sock.trace("UDPConn.send:start")
	if !sock.remote.IsValid() {
		return 0, nil // No remote address yet, yield.
	}

	available := min(sock.tx.Buffered(), len(response)-sizeUDPNoOptions)

	var payload []byte
	if available > 0 {
		payload = response[sizeUDPNoOptions : sizeUDPNoOptions+available] //this is a reference to the payload section of the response[] slice we are populating

		//we are reading out of the TX ring buffer, data to encapsulate and send
		n, err = sock.tx.Read(payload) //fill the payload section from the TX ring buffer

		if err != nil && err != io.EOF || n != int(available) {
			panic("bug in UDPCpn.send reading from TX buffer")
		}
	}

	sock.setSrcDest(&sock.pkt)
	sock.pkt.CalculateHeaders(payload)
	sock.pkt.PutHeaders(response) //the sock (conn object) has the local and remote port data to be able to embed in the packet

	return sizeUDPNoOptions + n, err
}

func (sock *UDPConn) setSrcDest(pkt *UDPPacket) {
	pkt.Eth.Source = sock.stack.HardwareAddr6()
	pkt.IP.Source = sock.stack.ip
	pkt.UDP.SourcePort = sock.localPort

	pkt.IP.Destination = sock.remote.Addr().As4()
	pkt.UDP.DestinationPort = sock.remote.Port()
	pkt.Eth.Destination = sock.remoteMAC
}

func (sock *UDPConn) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(sock.stack.logger, internal.LevelTrace, msg, attrs...)
}

package stacks

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"

	"github.com/soypat/seqs"
)

var _ net.Listener = (*TCPListener)(nil)

type TCPListenerConfig struct {
	MaxConnections uint16
	ConnTxBufSize  uint16
	ConnRxBufSize  uint16
}

type TCPListener struct {
	stack  *PortStack
	conns  []TCPConn
	used   []bool
	iss    seqs.Value
	port   uint16
	connid uint8
	open   bool
	laddr  net.TCPAddr
}

func NewTCPListener(stack *PortStack, cfg TCPListenerConfig) (*TCPListener, error) {
	if cfg.MaxConnections == 0 || (cfg.ConnRxBufSize < 64 && cfg.ConnTxBufSize < 64) {
		return nil, errors.New("bad TCPListenerConfig")
	}
	l := &TCPListener{
		stack: stack,
		conns: make([]TCPConn, cfg.MaxConnections),
		used:  make([]bool, cfg.MaxConnections),
	}
	cfgconn := TCPConnConfig{
		TxBufSize: cfg.ConnTxBufSize,
		RxBufSize: cfg.ConnRxBufSize,
	}
	for i := range l.conns {
		l.conns[i] = makeTCPConn(stack, cfgconn)
	}
	return l, nil
}

// Accept waits for and returns the next connection to the listener.
// It implements the [net.Listener] interface.
func (l *TCPListener) Accept() (net.Conn, error) {
	connid := l.connid
	for l.isOpen() && connid == l.connid {
		for i := range l.conns {
			conn := &l.conns[i]
			if l.used[i] || conn.State() != seqs.StateEstablished {
				continue
			}
			l.used[i] = true
			return conn, nil
		}
		runtime.Gosched()
	}
	return nil, net.ErrClosed
}

func (l *TCPListener) StartListening(port uint16) error {
	if l.isOpen() {
		return errors.New("already listening")
	}
	err := l.stack.OpenTCP(port, l)
	if err != nil {
		return err
	}
	l.port = port
	l.open = true
	for i := range l.conns {
		l.freeConnForReuse(i)
	}
	return nil
}

func (l *TCPListener) Close() error {
	if l.isOpen() {
		return errors.New("already closed")
	}
	return l.stack.CloseTCP(l.port)
}

// Addr returns the listener's network address. Implements [net.Listener].
func (l *TCPListener) Addr() net.Addr {
	l.laddr = net.TCPAddr{
		IP:   l.stack.Addr().AsSlice(),
		Port: int(l.port),
	}
	return &l.laddr
}

func (l *TCPListener) send(dst []byte) (n int, err error) {
	if !l.isOpen() {
		return 0, io.EOF
	}
	for i := range l.conns {
		conn := &l.conns[i]
		if conn.LocalPort() == 0 || !conn.isPendingHandling() {
			continue
		}
		n, err = conn.send(dst)
		if err == io.EOF {
			conn.abort()
		}
		if n > 0 {
			return n, ErrFlagPending
		}
	}
	return 0, nil
}

func (l *TCPListener) recv(pkt *TCPPacket) error {
	if !l.isOpen() {
		return io.EOF
	}
	var freeconn *TCPConn
	isSYN := pkt.TCP.Flags().HasAny(seqs.FlagSYN)
	for i := range l.conns {
		conn := &l.conns[i]
		if !l.used[i] {
			if freeconn == nil {
				freeconn = conn // Get first available connection in list.
				if isSYN {
					break // If SYN, use this TCPConn for new connection.
				}
			}
			continue
		}
		if pkt.TCP.SourcePort != conn.LocalPort() ||
			pkt.IP.Source != conn.remote.Addr().As4() {
			continue // Not for this connection.
		}
		err := conn.recv(pkt)
		if err == io.EOF {
			conn.abort()
			return nil
		}
		return err
	}
	if freeconn == nil {
		return ErrDroppedPacket // No available connection to receive packet.
	}
	err := freeconn.recv(pkt)
	if err == io.EOF {
		freeconn.abort()
		return nil
	}
	return err
}

func (l *TCPListener) abort() {
	l.open = false
	l.connid++
	for i := range l.conns {
		conn := &l.conns[i]
		if conn.LocalPort() != 0 {
			conn.abort()
		}
	}
}

func (l *TCPListener) freeConnForReuse(idx int) {
	conn := &l.conns[idx]
	conn.abort()
	conn.open(seqs.StateListen, l.port, l.iss, [6]byte{}, netip.AddrPort{})
	l.iss += 3237
	l.used[idx] = false
}

func (l *TCPListener) isPendingHandling() bool {
	return l.isOpen()
}

func (l *TCPListener) isOpen() bool { return l.open }

func (l *TCPListener) PortStack() *PortStack { return l.stack }

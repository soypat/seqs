package stacks

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/internal"
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
	const minBufSize = 10
	if cfg.MaxConnections == 0 || (cfg.ConnRxBufSize < minBufSize && cfg.ConnTxBufSize < minBufSize) {
		return nil, errors.New("bad TCPListenerConfig")
	}
	l := &TCPListener{
		stack: stack,
		conns: make([]TCPConn, cfg.MaxConnections),
		used:  make([]bool, cfg.MaxConnections),
	}
	txlen := int(cfg.ConnTxBufSize)
	rxlen := int(cfg.ConnRxBufSize)
	buf := make([]byte, int(cfg.MaxConnections)*(txlen+rxlen))
	for i := range l.conns {
		offset := i * (txlen + rxlen)
		tx := buf[offset : offset+txlen]
		rx := buf[offset+txlen : offset+txlen+rxlen]
		l.conns[i] = makeTCPConn(stack, tx, rx)
	}
	return l, nil
}

// Accept waits for and returns the next connection to the listener.
// It implements the [net.Listener] interface.
func (l *TCPListener) Accept() (net.Conn, error) {
	connid := l.connid
	backoff := internal.NewBackoff(internal.BackoffCriticalPath)
	for l.isOpen() && connid == l.connid {
		for i := range l.conns {
			conn := &l.conns[i]
			if l.used[i] || conn.State() != seqs.StateEstablished {
				continue
			}
			l.used[i] = true
			return conn, nil
		}
		backoff.Miss()
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
		IP:   l.stack.ip[:],
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
			l.freeConnForReuse(i)
			err = nil
		}
		if n > 0 {
			return n, err
		}
	}
	l.trace("lst:noconn2snd")
	return 0, nil
}

func (l *TCPListener) recv(pkt *TCPPacket) error {
	if !l.isOpen() {
		return io.EOF
	}
	l.stack.trace("lst:recv", slog.Uint64("lport", uint64(l.port)), slog.Uint64("rport", uint64(pkt.TCP.SourcePort)))
	var freeconn *TCPConn
	isSYN := pkt.TCP.Ack == 0 && pkt.TCP.Flags() == seqs.FlagSYN
	var connidx int
	if isSYN {
		for connidx = range l.conns {
			conn := &l.conns[connidx]
			if conn.scb.State() == seqs.StateListen && !conn.scb.HasPending() {
				// Get first available connection in list for first SYN packet, initiating connection.
				if l.used[connidx] {
					// See https://github.com/soypat/seqs/issues/25.
					l.stack.trace("lst:reuse-conn", slog.Uint64("rport", uint64(pkt.TCP.SourcePort)), slog.Uint64("rport-old", uint64(conn.remote.Port())))
				}
				freeconn = conn
				break
			}
		}
	} else {
		for connidx = range l.conns {
			conn := &l.conns[connidx]
			isMatch := pkt.TCP.SourcePort == conn.remote.Port() && pkt.IP.Source == conn.remote.Addr().As4()
			if isMatch {
				freeconn = conn
				break
			}
		}
	}
	if freeconn == nil {
		l.trace("lst:noconn2recv")
		return ErrDroppedPacket // No available connection to receive packet.
	}
	err := freeconn.recv(pkt)
	if err == io.EOF {
		l.freeConnForReuse(connidx)
		freeconn.abort()
		err = nil
	}
	return err
}

func (l *TCPListener) abort() {
	l.info("lst:abort", slog.Uint64("lport", uint64(l.port)))
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
	l.iss = prand32(l.iss)
	conn := &l.conns[idx]
	l.info("lst:freeConnForReuse", slog.Uint64("lport", uint64(conn.localPort)), slog.Uint64("rport", uint64(conn.remote.Port())))
	conn.abort()
	conn.open(seqs.StateListen, l.port, l.iss, [6]byte{}, netip.AddrPort{})
	l.used[idx] = false
}

func (l *TCPListener) isPendingHandling() bool {
	return l.isOpen()
}

func (l *TCPListener) isOpen() bool { return l.open }

func (l *TCPListener) PortStack() *PortStack { return l.stack }

func (l *TCPListener) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.stack.logger, internal.LevelTrace, msg, attrs...)
}

func (l *TCPListener) info(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(l.stack.logger, slog.LevelInfo, msg, attrs...)
}

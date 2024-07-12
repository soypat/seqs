package stacks

//UDP is 'connectionless' so this is only a connection in so far as it's a bunch of packets arriving on a common port
//Packets can fail to arrive, or arrive out of order, or arrive more than once - this is the nature of UDP
//It is very easy to build a reliable protocol on top of UDP

import (	
	"io"
	"log/slog"
	"net"     
	"net/netip"	
	"time"	
	"github.com/soypat/seqs/internal"
	"github.com/soypat/seqs/eth"	
)

var _ net.Conn = &UDPConn{}  //net.conn is part of the standard go library - it's an interface we must implement

//The handler is a set of methods (primarily send and recv) that the underlying port stack will call, to pass packets for processing
//it is an interface we need to implement
var handler iudphandler = (*UDPConn)(nil)

var defaultUDPbuffSize=uint16(4096) //a bit arbitrary

const (
	//defaultSocketSize = 2048
	sizeUDPNoOptions  = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
)


type UDPConn struct {
	stack  *PortStack	
	lastRx time.Time
	pkt    UDPPacket //this is a reusable 'scratchpad' packet used for sending	
	tx     ring  //the ring buffers contain unpacketised data
	rx     ring	
	remote    netip.AddrPort
	localPort uint16
	remoteMAC [6]byte //this is the ROUTER/Gateways mac address .. it's not a great name (IMHO) - unless it isn't in which case I appologise
	
}

//this is an identical structure to TCPConnConfig - but I didn't want to change the original name without discussions
type BuffConfig struct { 
	TxBufSize uint16
	RxBufSize uint16
}

func NewUDPConn(stack *PortStack, cfg BuffConfig) (*UDPConn, error) {
	
	if cfg.RxBufSize == 0 {
			cfg.RxBufSize = defaultUDPbuffSize
	}
	if cfg.TxBufSize == 0 {
		cfg.TxBufSize = defaultUDPbuffSize
	}

	buf := make([]byte, cfg.RxBufSize+cfg.TxBufSize) //I guess slicing this single buffer is a heap allocation optimisation or something - but I'm not really a fan TX and RX buffers would be a lot more readable
	
	sock := makeUDPConn(stack, buf[:cfg.TxBufSize], buf[cfg.TxBufSize:cfg.TxBufSize+cfg.RxBufSize])
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
		
	sock.trace("UDPConn.OpenDialUDP:start")
	return sock.openstack( localPort,remoteMAC, remote)

}

func (sock *UDPConn) openstack(localPortNum uint16, remoteMAC [6]byte, remote netip.AddrPort) error { //}, iss seqs.Value, remoteMAC [6]byte, remoteAddr netip.AddrPort) error {
	
	sock.stack.OpenUDP(localPortNum, sock)
	err := sock.open(localPortNum,  remoteMAC, remote)

	return err
	
}

func (sock *UDPConn) open( localPortNum uint16, remoteMAC [6]byte, remoteAddr netip.AddrPort) error {
	
	// err := sock.scb.Open(iss, seqs.Size(len(sock.rx.buf)), state)
	// if err != nil {
	// 	return err
	// }
	// sock.scb.SetLogger(sock.stack.logger)
	sock.remoteMAC = remoteMAC //this is our router/gateway MAC address - we never get to know the remote MAC address (that would be a security issue)
	sock.remote = remoteAddr
	sock.localPort = localPortNum
	sock.rx.Reset()
	sock.tx.Reset()
	
	return nil
}


func (u *UDPConn) abort() {
    // There is no connection per se to abort
	
}

func (u *UDPConn) SetReadDeadline(t time.Time) error  {
    // not really relevant to UDP - buit the interface requires it
	return nil
}

func (u *UDPConn) SetWriteDeadline(t time.Time) error  {
    // not really relevant to UDP
	return nil
}

func (sock *UDPConn) isPendingHandling() bool  {
    
	// much simpler than TCP - may need expanding??
	return (sock.tx.Buffered()>0) || (sock.rx.Buffered() > 0 )
	
}


// Reads from the underlying rx ring buffer, throws an EOF error if no data is available
func (u *UDPConn) Read(b []byte) (n int, err error) {    
	return u.rx.Read(b) //read from the rx ring buffer into b    
}

// Writes into the underlying tx ring buffer - calls to the portStacks handleEth() will send the (queued) data
func (sock *UDPConn) Write(b []byte) (n int, err error) {    
	err = sock.stack.FlagPendingUDP(sock.localPort)	
	if err != nil {panic ("flagpending error")} //@@@REMOVE ?
    return sock.tx.Write(b)
}


func (u *UDPConn) Close() error {    
    return nil
}

// LocalAddr implements the LocalAddr method of the net.Conn interface.
func (u *UDPConn) LocalAddr() net.Addr {
    // Implement the method

    return u.LocalAddr()
}

// RemoteAddr implements the RemoteAddr method of the net.Conn interface.
func (u *UDPConn) RemoteAddr() net.Addr {
    // Implement the method
    return nil
}


func (u *UDPConn) SetDeadline(t time.Time) error {
    // Implement the method
    return nil
}

func (sock *UDPConn) trace(msg string, attrs ...slog.Attr) {
	internal.LogAttrs(sock.stack.logger, internal.LevelTrace, msg, attrs...)
}


//takes (the contents of ) a packet it and puts it in the RX ring buffer
func (sock *UDPConn) recv(pkt *UDPPacket) (err error) {
	sock.trace("UDP.recv:start")
	
	remotePort := sock.remote.Port()
	if remotePort != 0 && pkt.UDP.SourcePort != remotePort {
		return nil // This packet came from a different client (remote port) to the one we are interacting with.
	}
	sock.lastRx = pkt.Rx
	// By this point we know that the packet is valid and contains data, we process it.
	payload := pkt.Payload()	
	_, err = sock.rx.Write(payload) //write into the UDPconns rx (ring) buffer
	
	return err  //which is hopefully nil - but could be errRingBufferFull
}

//this handler is called regularly by the underlying stack (HandleEth) and populates response[] from the TX ring buffer, with data to be sent as a packet
func (sock *UDPConn) send(response []byte) (n int, err error) {
	
	defer sock.trace("UDPConn.send:start")  //why is this deferred ? - coul dbe confusing

	if !sock.remote.IsValid() {
		return 0, nil // No remote address yet, yield.
	}
	
	available := min(sock.tx.Buffered(), len(response)-sizeUDPNoOptions)

	
	var payload []byte
	if available > 0 {
		payload = response[sizeUDPNoOptions : sizeUDPNoOptions+available]  //this is a reference to the payload section of the response[] slice we are populating

		//we are reading out of the TX ring buffer, data to encapsulate and send 
		n, err = sock.tx.Read(payload) //fill the payload section from the TX ring buffer

		//println("payload filled with ",string(payload)) //@@@REMOVE

		if err != nil && err != io.EOF || n != int(available) {
			panic("bug in handleUser") // This is a bug in ring buffer or a race condition. - is it ? - odd message then
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


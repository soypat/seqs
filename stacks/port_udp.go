package stacks

import (
	"strconv"
	"time"

	"github.com/soypat/seqs/eth"
)

type udphandler func(response []byte, pkt *UDPPacket) (int, error)
type iudphandler interface {
	send(dst []byte) (n int, err error)
	recv(pkt *UDPPacket) error
	// needsHandling() bool
	isPendingHandling() bool
	abort()
}

type udpPort struct {
	LastRx   time.Time
	handler  udphandler
	ihandler iudphandler
	port     uint16
	pkt      UDPPacket
	packets  [1]UDPPacket
}

func (port udpPort) Port() uint16 { return port.port }

// NeedsHandling returns true if the socket needs handling before it can
// admit more pending packets.
func (port *udpPort) NeedsHandling() bool {
	return port.freePacket() == nil
}

// IsPendingHandling returns true if there are packet(s) pending handling.
func (port *udpPort) IsPendingHandling() bool {
	// return port.port != 0 && port.ihandler.isPendingHandling()
	return port.port != 0 && port.nextPacket().pendingHandling()
}

// HandleEth writes the socket's response into dst to be sent over an ethernet interface.
// HandleEth can return 0 bytes written and a nil error to indicate no action must be taken.
func (port *udpPort) HandleEth(dst []byte) (int, error) {
	if port.ihandler == nil {
		panic("nil udp handler on port " + strconv.Itoa(int(port.port)))
	}
	packet := port.nextPacket()
	// n,err := port.ihandler.send(d)
	// n, err := port.handler(dst, packet)
	n, err := port.ihandler.send(dst)
	if err == ErrFlagPending {
		packet.flagPendingNoPacket() // Mark socket as needing handling but packet having no data.
	} else {
		packet.invalidate()
	}
	return n, err
}

// Open sets the UDP handler and opens the port.
func (port *udpPort) Open(portNum uint16, h iudphandler) {
	if portNum == 0 || h == nil {
		panic("invalid port or nil handler" + strconv.Itoa(int(port.port)))
	} else if port.port != 0 {
		panic("port already open")
	}
	port.ihandler = h
	port.port = portNum
}

func (port *udpPort) pending() (p int) {
	for i := range port.packets {
		if port.packets[i].pendingHandling() {
			p++
		}
	}
	return p
}

func (port *udpPort) Close() {
	port.port = 0 // Port 0 flags the port is inactive.
	for i := range port.packets {
		port.packets[i].invalidate()
	}
}

// nextPacket returns the next packet that is pending handling or the first packet if none are pending.
func (port *udpPort) nextPacket() *UDPPacket {
	for i := range port.packets {
		if port.packets[i].pendingHandling() {
			return &port.packets[i]
		}
	}
	return &port.packets[0]
}

// freePacket returns the first packet that is not pending handling or nil if all packets are pending.
func (port *udpPort) freePacket() *UDPPacket {
	for i := range port.packets {
		if !port.packets[i].pendingHandling() {
			return &port.packets[i]
		}
	}
	return nil
}

// UDP socket can be forced to respond even if no packet has been received
// by flagging the packet's Rx time with non-zero value.
var forcedTime = (time.Time{}).Add(1)

func (port *udpPort) forceResponse() (added bool) {
	for i := range port.packets {
		if !port.packets[i].pendingHandling() {
			port.packets[i].flagPendingNoPacket()
			return true
		}
	}
	return false
}

type UDPPacket struct {
	Rx      time.Time
	Eth     eth.EthernetHeader
	IP      eth.IPv4Header
	UDP     eth.UDPHeader
	payload [defaultMTU - eth.SizeEthernetHeader - eth.SizeIPv4Header - eth.SizeUDPHeader]byte
}

func (pkt *UDPPacket) HasPacket() bool       { return pkt != nil && pkt.Rx != forcedTime && !pkt.Rx.IsZero() }
func (pkt *UDPPacket) pendingHandling() bool { return !pkt.Rx.IsZero() }
func (pkt *UDPPacket) invalidate()           { pkt.Rx = time.Time{} }
func (pkt *UDPPacket) flagPendingNoPacket()  { pkt.Rx = forcedTime }

func (pkt *UDPPacket) PutHeaders(b []byte) {
	if len(b) < eth.SizeEthernetHeader+eth.SizeIPv4Header+eth.SizeUDPHeader {
		panic("short UDPPacket buffer")
	}
	if pkt.IP.IHL() != 5 {
		panic("UDPPacket.PutHeaders expects no IP options")
	}
	pkt.Eth.Put(b)
	pkt.IP.Put(b[eth.SizeEthernetHeader:])
	pkt.UDP.Put(b[eth.SizeEthernetHeader+eth.SizeIPv4Header:])
}

// Payload returns the UDP payload. If UDP or IPv4 header data is incorrect/bad it returns nil.
// If the response is "forced" then payload will be nil.
func (pkt *UDPPacket) Payload() []byte {
	if !pkt.HasPacket() {
		return nil
	}
	ipLen := int(pkt.IP.TotalLength) - int(pkt.IP.IHL()*4) - eth.SizeUDPHeader // Total length(including header) - header length = payload length
	uLen := int(pkt.UDP.Length) - eth.SizeUDPHeader
	if ipLen != uLen || uLen > len(pkt.payload) {
		return nil // Mismatching IP and UDP data or bad length.
	}
	return pkt.payload[:uLen]
}

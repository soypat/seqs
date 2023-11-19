package stack

import (
	"io"
	"strconv"
	"time"

	"github.com/soypat/seqs/eth"
)

type udphandler func(response []byte, pkt *UDPPacket) (int, error)

type udpPort struct {
	LastRx  time.Time
	handler udphandler
	Port    uint16
	packets [1]UDPPacket
}

type UDPPacket struct {
	Rx      time.Time
	Eth     eth.EthernetHeader
	IP      eth.IPv4Header
	UDP     eth.UDPHeader
	payload [_MTU - eth.SizeEthernetHeader - eth.SizeIPv4Header - eth.SizeUDPHeader]byte
}

// NeedsHandling returns true if the socket needs handling before it can
// admit more pending packets.
func (u *udpPort) NeedsHandling() bool {
	// As of now socket has space for 1 packet so if packet is pending, queue is full.
	// Compile time check to ensure this is fulfilled:
	_ = u.packets[1-len(u.packets)]
	return u.IsPendingHandling()
}

// IsPendingHandling returns true if there are packet(s) pending handling.
func (u *udpPort) IsPendingHandling() bool {
	return u.Port != 0 && !u.packets[0].Rx.IsZero()
}

// HandleEth writes the socket's response into dst to be sent over an ethernet interface.
// HandleEth can return 0 bytes written and a nil error to indicate no action must be taken.
// If
func (u *udpPort) HandleEth(dst []byte) (int, error) {
	if u.handler == nil {
		panic("nil udp handler on port " + strconv.Itoa(int(u.Port)))
	}
	packet := &u.packets[0]

	n, err := u.handler(dst, &u.packets[0])
	if err != io.ErrNoProgress {
		packet.Rx = time.Time{} // Invalidate packet.
	}
	return n, err
}

// Open sets the UDP handler and opens the port.
func (u *udpPort) Open(port uint16, h udphandler) {
	if port == 0 || h == nil {
		panic("invalid port or nil handler" + strconv.Itoa(int(u.Port)))
	}
	u.handler = h
	u.Port = port
}

func (s *udpPort) pending() (p int) {
	for i := range s.packets {
		if s.packets[i].HasPacket() {
			p++
		}
	}
	return p
}

func (u *udpPort) Close() {
	u.Port = 0 // Port 0 flags the port is inactive.
	for i := range u.packets {
		u.packets[i].Rx = time.Time{} // Invalidate packets.
	}
}

// UDP socket can be forced to respond even if no packet has been received
// by flagging the packet's Rx time with non-zero value.
var forcedTime = (time.Time{}).Add(1)

func (u *udpPort) forceResponse() (added bool) {
	if !u.IsPendingHandling() {
		added = true
		u.packets[0].Rx = forcedTime
	}
	return added
}

func (u *UDPPacket) HasPacket() bool {
	return u.Rx != forcedTime && !u.Rx.IsZero() // TODO simplify this to just IsZero
}

func (p *UDPPacket) PutHeaders(b []byte) {
	if len(b) < eth.SizeEthernetHeader+eth.SizeIPv4Header+eth.SizeUDPHeader {
		panic("short UDPPacket buffer")
	}
	if p.IP.IHL() != 5 {
		panic("UDPPacket.PutHeaders expects no IP options")
	}
	p.Eth.Put(b)
	p.IP.Put(b[eth.SizeEthernetHeader:])
	p.UDP.Put(b[eth.SizeEthernetHeader+eth.SizeIPv4Header:])
}

// Payload returns the UDP payload. If UDP or IPv4 header data is incorrect/bad it returns nil.
// If the response is "forced" then payload will be nil.
func (p *UDPPacket) Payload() []byte {
	if !p.HasPacket() {
		return nil
	}
	ipLen := int(p.IP.TotalLength) - int(p.IP.IHL()*4) - eth.SizeUDPHeader // Total length(including header) - header length = payload length
	uLen := int(p.UDP.Length) - eth.SizeUDPHeader
	if ipLen != uLen || uLen > len(p.payload) {
		return nil // Mismatching IP and UDP data or bad length.
	}
	return p.payload[:uLen]
}
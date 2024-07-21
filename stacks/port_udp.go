package stacks

import (
	"strconv"
	"time"

	"github.com/soypat/seqs/eth"
)

type iudphandler interface {
	// putOutboundEth is called by the underlying stack [PortStack.PutOutboundEth] method and populates
	// response from the TX ring buffer, with data to be sent as a packet and returns n bytes written.
	// See [PortStack] for more information.
	putOutboundEth(response []byte) (n int, err error)
	recvEth(pkt *UDPPacket) error
	// needsHandling() bool
	isPendingHandling() bool
	abort()
}

type udpPort struct {
	handler iudphandler
	port    uint16
}

func (port udpPort) Port() uint16 { return port.port }

// IsPendingHandling returns true if there are packet(s) pending handling.
func (port *udpPort) IsPendingHandling() bool {
	// return port.port != 0 && port.ihandler.isPendingHandling()
	return port.port != 0 && port.handler.isPendingHandling()
}

// PutOutboundEth writes the socket's response into dst to be sent over an ethernet interface.
// PutOutboundEth can return 0 bytes written and a nil error to indicate no action must be taken.
func (port *udpPort) PutOutboundEth(dst []byte) (int, error) {

	if port.handler == nil {
		panic("nil udp handler on port " + strconv.Itoa(int(port.port)))
	}

	return port.handler.putOutboundEth(dst)
}

// Open sets the UDP handler and opens the port.
// This is effectively a constructor for the port NewUDPPort() - would be an alternative name
func (port *udpPort) Open(portNum uint16, h iudphandler) {
	if portNum == 0 || h == nil {
		panic("invalid port or nil handler" + strconv.Itoa(int(port.port)))
	} else if port.port != 0 {
		panic("port already open")
	}
	port.handler = h
	port.port = portNum
}

func (port *udpPort) Close() {
	port.port = 0 // Port 0 flags the port is inactive.
	port.handler = nil
}

// UDP socket can be forced to respond even if no packet has been received
// by flagging the packet's Rx time with non-zero value.
var forcedTime = (time.Time{}).Add(1)

type UDPPacket struct {
	Rx      time.Time
	Eth     eth.EthernetHeader
	IP      eth.IPv4Header
	UDP     eth.UDPHeader
	payload [defaultMTU - eth.SizeEthernetHeader - eth.SizeIPv4Header - eth.SizeUDPHeader]byte
}

func (pkt *UDPPacket) PutHeaders(b []byte) {
	if len(b) < eth.SizeEthernetHeader+eth.SizeIPv4Header+eth.SizeUDPHeader {
		panic("short UDPPacket buffer")
	}
	if pkt.IP.IHL() != 5 {
		panic("UDPPacket.PutHeaders expects no IP options " + strconv.Itoa(int(pkt.IP.IHL())))
	}
	pkt.Eth.Put(b)
	pkt.IP.Put(b[eth.SizeEthernetHeader:])
	pkt.UDP.Put(b[eth.SizeEthernetHeader+eth.SizeIPv4Header:])
}

// Payload returns the UDP payload. If UDP or IPv4 header data is incorrect/bad it returns nil.
// If the response is "forced" then payload will be nil.
func (pkt *UDPPacket) Payload() []byte {
	ipLen := int(pkt.IP.TotalLength) - int(pkt.IP.IHL()*4) - eth.SizeUDPHeader // Total length(including header) - header length = payload length
	uLen := int(pkt.UDP.Length) - eth.SizeUDPHeader
	if ipLen != uLen || uLen > len(pkt.payload) {
		return nil // Mismatching IP and UDP data or bad length.
	}
	return pkt.payload[:uLen]
}

func (pkt *UDPPacket) CalculateHeaders(payload []byte) {
	const ipLenInWords = 5
	pkt.Eth.SizeOrEtherType = uint16(eth.EtherTypeIPv4)

	// IPv4 frame.
	pkt.IP.Protocol = 17 // UDP
	pkt.IP.TTL = 64
	pkt.IP.ID = prand16(pkt.IP.ID)
	pkt.IP.VersionAndIHL = ipLenInWords // Sets IHL: No IP options. Version set automatically.
	pkt.IP.TotalLength = 4*ipLenInWords + eth.SizeUDPHeader + uint16(len(payload))
	// TODO(soypat): Document how to handle ToS. For now just use ToS used by other side.
	pkt.IP.Flags = 0 // packet.IP.ToS = 0
	pkt.IP.Checksum = pkt.IP.CalculateChecksum()

	pkt.UDP = eth.UDPHeader{
		SourcePort:      pkt.UDP.SourcePort,
		DestinationPort: pkt.UDP.DestinationPort,
		Checksum:        0,
		Length:          uint16(len(payload) + eth.SizeUDPHeader),
	}
	pkt.UDP.Checksum = pkt.UDP.CalculateChecksumIPv4(&pkt.IP, payload)
}

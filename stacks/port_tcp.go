package stacks

import (
	"errors"
	"strconv"
	"time"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
)

// tcphandler represents a user provided function for handling incoming TCP packets on a port.
// Incoming data is sent inside the `pkt` TCPPacket argument when pkt.HasPacket returns true.
// Outgoing data is stored into the `response` byte slice. The function must return the number of
// bytes written to `response` and an error.
//
// See [PortStack] for information on how to use this function and other port handlers.
type itcphandler interface {
	send(dst []byte) (n int, err error)
	recv(pkt *TCPPacket) error
	// needsHandling() bool
	isPendingHandling() bool
	abort()
}

type tcpPort struct {
	handler itcphandler
	port    uint16
	p       bool
}

func (port tcpPort) Port() uint16 { return port.port }

// IsPendingHandling returns true if there are packet(s) pending handling.
func (port *tcpPort) IsPendingHandling() bool {
	return port.port != 0 && port.handler.isPendingHandling()
}

// HandleEth writes the socket's response into dst to be sent over an ethernet interface.
// HandleEth can return 0 bytes written and a nil error to indicate no action must be taken.
func (port *tcpPort) HandleEth(dst []byte) (n int, err error) {
	if port.handler == nil {
		panic("nil tcp handler on port " + strconv.Itoa(int(port.port)))
	}

	n, err = port.handler.send(dst)
	port.p = false
	if err == ErrFlagPending {
		port.p = true
	}
	return n, err
}

// Open sets the UDP handler and opens the port.
func (port *tcpPort) Open(portNum uint16, handler itcphandler) {
	if portNum == 0 || handler == nil {
		panic("invalid port or nil handler" + strconv.Itoa(int(port.port)))
	} else if port.port != 0 {
		panic("port already open")
	}
	port.handler = handler
	port.port = portNum
	port.p = false
}

func (port *tcpPort) Close() {
	if port.handler != nil {
		port.handler.abort()
	}
	port.handler = nil
	port.port = 0 // Port 0 flags the port is inactive.
}

const tcpMTU = defaultMTU - eth.SizeEthernetHeader - eth.SizeIPv4Header - eth.SizeTCPHeader

type TCPPacket struct {
	Rx  time.Time
	Eth eth.EthernetHeader
	IP  eth.IPv4Header
	TCP eth.TCPHeader
	// data contains TCP+IP options and then the actual data.
	data [tcpMTU]byte
}

func (pkt *TCPPacket) String() string {
	payload := pkt.Payload()
	if len(payload) == 0 {
		return "TCP Packet: " + pkt.Eth.String() + " " + pkt.IP.String() + " " + pkt.TCP.String()
	}
	return "TCP Packet: " + pkt.Eth.String() + " " + pkt.IP.String() + " " + pkt.TCP.String() + " payload:" + strconv.Quote(string(pkt.Payload()))
}

// PutHeaders puts 54 bytes including the Ethernet, IPv4 and TCP headers into b.
// b must be at least 54 bytes in length or else PutHeaders panics. No options are marshalled.
func (pkt *TCPPacket) PutHeaders(b []byte) {
	const minSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
	if len(b) < minSize {
		panic("short tcpPacket buffer")
	}
	if pkt.IP.IHL() != 5 || pkt.TCP.Offset() != 5 {
		panic("TCPPacket.PutHeaders expects no IP or TCP options")
	}
	pkt.Eth.Put(b)
	pkt.IP.Put(b[eth.SizeEthernetHeader:])
	pkt.TCP.Put(b[eth.SizeEthernetHeader+eth.SizeIPv4Header:])
}

func (pkt *TCPPacket) PutHeadersWithOptions(b []byte) error {
	const minSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
	if len(b) < minSize {
		panic("short tcpPacket buffer")
	}
	panic("PutHeadersWithOptions not implemented")
}

// Payload returns the TCP payload. If TCP or IPv4 header data is incorrect/bad it returns nil.
// If the response is "forced" then payload will be nil.
func (pkt *TCPPacket) Payload() []byte {
	payloadStart, payloadEnd, _ := pkt.dataPtrs()
	if payloadStart < 0 {
		return nil // Bad header value
	}
	return pkt.data[payloadStart:payloadEnd]
}

// Options returns the TCP options in the packet.
func (pkt *TCPPacket) TCPOptions() []byte {
	payloadStart, _, tcpOptStart := pkt.dataPtrs()
	if payloadStart < 0 {
		return nil // Bad header value
	}
	return pkt.data[tcpOptStart:payloadStart]
}

// Options returns the TCP options in the packet.
func (pkt *TCPPacket) IPOptions() []byte {
	_, _, tcpOpts := pkt.dataPtrs()
	if tcpOpts < 0 {
		return nil // Bad header value
	}
	return pkt.data[:tcpOpts]
}

//go:inline
func (pkt *TCPPacket) dataPtrs() (payloadStart, payloadEnd, tcpOptStart int) {
	tcpOptStart = int(4*pkt.IP.IHL()) - eth.SizeIPv4Header
	payloadStart = tcpOptStart + int(pkt.TCP.OffsetInBytes()) - eth.SizeTCPHeader
	payloadEnd = int(pkt.IP.TotalLength) - tcpOptStart - eth.SizeTCPHeader - eth.SizeIPv4Header
	if payloadStart < 0 || payloadEnd < 0 || tcpOptStart < 0 || payloadStart > payloadEnd ||
		payloadEnd > len(pkt.data) || tcpOptStart > payloadStart {
		return -1, -1, -1
	}
	return payloadStart, payloadEnd, tcpOptStart
}

func (pkt *TCPPacket) InvertSrcDest() {
	pkt.IP.Destination, pkt.IP.Source = pkt.IP.Source, pkt.IP.Destination
	pkt.Eth.Destination, pkt.Eth.Source = pkt.Eth.Source, pkt.Eth.Destination
	pkt.TCP.DestinationPort, pkt.TCP.SourcePort = pkt.TCP.SourcePort, pkt.TCP.DestinationPort
}

func (pkt *TCPPacket) CalculateHeaders(seg seqs.Segment, payload []byte) {
	const ipLenInWords = 5
	if int(seg.DATALEN) != len(payload) {
		panic("seg.DATALEN != len(payload)")
	}
	// Ethernet frame.
	pkt.Eth.SizeOrEtherType = uint16(eth.EtherTypeIPv4)

	// IPv4 frame.
	pkt.IP.Protocol = 6 // TCP.
	pkt.IP.TTL = 64
	pkt.IP.ID = prand16(pkt.IP.ID)
	pkt.IP.VersionAndIHL = ipLenInWords // Sets IHL: No IP options. Version set automatically.
	pkt.IP.TotalLength = 4*ipLenInWords + eth.SizeTCPHeader + uint16(len(payload))
	// TODO(soypat): Document how to handle ToS. For now just use ToS used by other side.
	pkt.IP.Flags = 0 // packet.IP.ToS = 0
	pkt.IP.Checksum = pkt.IP.CalculateChecksum()

	// TCP frame.
	const offset = 5

	pkt.TCP = eth.TCPHeader{
		SourcePort:      pkt.TCP.SourcePort,
		DestinationPort: pkt.TCP.DestinationPort,
		Seq:             seg.SEQ,
		Ack:             seg.ACK,
		WindowSizeRaw:   uint16(seg.WND),
		UrgentPtr:       0, // We do not implement urgent pointer.
	}
	pkt.TCP.SetFlags(seg.Flags)
	pkt.TCP.SetOffset(offset)
	pkt.TCP.Checksum = pkt.TCP.CalculateChecksumIPv4(&pkt.IP, nil, payload)
}

// prand16 generates a pseudo random number from a seed.
func prand16(seed uint16) uint16 {
	// 16bit Xorshift  https://en.wikipedia.org/wiki/Xorshift
	seed ^= seed << 7
	seed ^= seed >> 9
	seed ^= seed << 8
	return seed
}

// prand32 generates a pseudo random number from a seed.
func prand32[T ~uint32](seed T) T {
	/* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}

// ParseTCPPacket is a convenience function for generating a pkt TCP packet
//
// Deprecated: This function is guaranteed to disappear in the future. Used only in tests.
func ParseTCPPacket(b []byte) (pkt TCPPacket, err error) {
	if len(b) < eth.SizeEthernetHeader+eth.SizeIPv4Header+eth.SizeTCPHeader {
		return TCPPacket{}, errors.New("short packet")
	}
	pkt.Eth = eth.DecodeEthernetHeader(b)
	if pkt.Eth.AssertType() != eth.EtherTypeIPv4 {
		return pkt, errors.New("not ipv4")
	}
	var offset uint8
	pkt.IP, offset = eth.DecodeIPv4Header(b[eth.SizeEthernetHeader:])
	if int(eth.SizeEthernetHeader+offset) > len(b) {
		return pkt, errors.New("short packet or bad IP.IHL")
	} else if uint16(offset) > pkt.IP.TotalLength {
		return pkt, errors.New("bad ip.IHL or bad IP.TotalLength")
	} else if int(pkt.IP.TotalLength+eth.SizeEthernetHeader) > len(b) {
		return pkt, errors.New("short packet or bad IP.TotalLength")
	}
	ipOptions := b[eth.SizeEthernetHeader+eth.SizeIPv4Header : eth.SizeEthernetHeader+offset]
	ipPayload := b[eth.SizeEthernetHeader+offset:]
	if pkt.IP.Protocol != 6 {
		return pkt, errors.New("not tcp")
	} else if uint16(offset) > pkt.IP.TotalLength {
		return pkt, errors.New("bad TCP.Offset (greater than IP.TotalLength)")
	}
	pkt.TCP, offset = eth.DecodeTCPHeader(ipPayload)
	tcpOptions := ipPayload[eth.SizeTCPHeader:offset]
	tcpPayload := ipPayload[offset:pkt.IP.TotalLength]
	n := copy(pkt.data[:], ipOptions)
	n += copy(pkt.data[n:], tcpOptions)
	copy(pkt.data[n:], tcpPayload)

	pkt.Rx = forcedTime.Add(1) // Mark packet as containing data.
	return pkt, nil
}

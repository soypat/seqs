package stack

import (
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
)

type tcphandler func(response []byte, pkt *TCPPacket) (int, error)

type tcpPort struct {
	LastRx  time.Time
	handler tcphandler
	Port    uint16
	packets [1]TCPPacket
}

const tcpMTU = _MTU - eth.SizeEthernetHeader - eth.SizeIPv4Header - eth.SizeTCPHeader

type TCPPacket struct {
	Rx  time.Time
	Eth eth.EthernetHeader
	IP  eth.IPv4Header
	TCP eth.TCPHeader
	// data contains TCP+IP options and then the actual data.
	data [tcpMTU]byte
}

func (p *TCPPacket) String() string {
	return "TCP Packet: " + p.Eth.String() + " " + p.IP.String() + " " + p.TCP.String() + " payload:" + strconv.Quote(string(p.Payload()))
}

// NeedsHandling returns true if the socket needs handling before it can
// admit more pending packets.
func (u *tcpPort) NeedsHandling() bool {
	// As of now socket has space for 1 packet so if packet is pending, queue is full.
	// Compile time check to ensure this is fulfilled:
	_ = u.packets[1-len(u.packets)]
	return u.IsPendingHandling()
}

// IsPendingHandling returns true if there are packet(s) pending handling.
func (u *tcpPort) IsPendingHandling() bool {
	return u.Port != 0 && !u.packets[0].Rx.IsZero()
}

// HandleEth writes the socket's response into dst to be sent over an ethernet interface.
// HandleEth can return 0 bytes written and a nil error to indicate no action must be taken.
// If
func (u *tcpPort) HandleEth(dst []byte) (n int, err error) {
	if u.handler == nil {
		panic("nil tcp handler on port " + strconv.Itoa(int(u.Port)))
	}
	packet := &u.packets[0]

	n, err = u.handler(dst, &u.packets[0])
	if err != io.ErrNoProgress {
		packet.Rx = time.Time{} // Invalidate packet.
	}
	return n, err
}

// Open sets the UDP handler and opens the port.
func (u *tcpPort) Open(port uint16, handler tcphandler) {
	if port == 0 || handler == nil {
		panic("invalid port or nil handler" + strconv.Itoa(int(u.Port)))
	}
	u.handler = handler
	u.Port = port
	for i := range u.packets {
		u.packets[i].Rx = time.Time{} // Invalidate packets.
	}
}

func (s *tcpPort) pending() (p uint32) {
	for i := range s.packets {
		if s.packets[i].HasPacket() {
			p++
		}
	}
	return p
}

func (u *tcpPort) Close() {
	u.handler = nil
	u.Port = 0 // Port 0 flags the port is inactive.
}

func (u *tcpPort) forceResponse() (added bool) {
	if !u.IsPendingHandling() {
		added = true
		u.packets[0].Rx = forcedTime
	}
	return added
}

func (u *TCPPacket) HasPacket() bool {
	return u.Rx != forcedTime && !u.Rx.IsZero()
}

// PutHeaders puts 54 bytes including the Ethernet, IPv4 and TCP headers into b.
// b must be at least 54 bytes in length or else PutHeaders panics. No options are marshalled.
func (p *TCPPacket) PutHeaders(b []byte) {
	const minSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
	if len(b) < minSize {
		panic("short tcpPacket buffer")
	}
	if p.IP.IHL() != 5 || p.TCP.Offset() != 5 {
		panic("TCPPacket.PutHeaders expects no IP or TCP options")
	}
	p.Eth.Put(b)
	p.IP.Put(b[eth.SizeEthernetHeader:])
	p.TCP.Put(b[eth.SizeEthernetHeader+eth.SizeIPv4Header:])
}

func (p *TCPPacket) PutHeadersWithOptions(b []byte) error {
	const minSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader
	if len(b) < minSize {
		panic("short tcpPacket buffer")
	}
	panic("PutHeadersWithOptions not implemented")
}

// Payload returns the TCP payload. If TCP or IPv4 header data is incorrect/bad it returns nil.
// If the response is "forced" then payload will be nil.
func (p *TCPPacket) Payload() []byte {
	if !p.HasPacket() {
		return nil
	}
	payloadStart, payloadEnd, _ := p.dataPtrs()
	if payloadStart < 0 {
		return nil // Bad header value
	}
	return p.data[payloadStart:payloadEnd]
}

// Options returns the TCP options in the packet.
func (p *TCPPacket) TCPOptions() []byte {
	if !p.HasPacket() {
		return nil
	}
	payloadStart, _, tcpOptStart := p.dataPtrs()
	if payloadStart < 0 {
		return nil // Bad header value
	}
	return p.data[tcpOptStart:payloadStart]
}

// Options returns the TCP options in the packet.
func (p *TCPPacket) IPOptions() []byte {
	if !p.HasPacket() {
		return nil
	}
	_, _, tcpOpts := p.dataPtrs()
	if tcpOpts < 0 {
		return nil // Bad header value
	}
	return p.data[:tcpOpts]
}

//go:inline
func (p *TCPPacket) dataPtrs() (payloadStart, payloadEnd, tcpOptStart int) {
	tcpOptStart = int(4*p.IP.IHL()) - eth.SizeIPv4Header
	payloadStart = tcpOptStart + int(p.TCP.OffsetInBytes()) - eth.SizeTCPHeader
	payloadEnd = int(p.IP.TotalLength) - tcpOptStart - eth.SizeTCPHeader - eth.SizeIPv4Header
	if payloadStart < 0 || payloadEnd < 0 || tcpOptStart < 0 || payloadStart > payloadEnd ||
		payloadEnd > len(p.data) || tcpOptStart > payloadStart {
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
	pkt.IP.Checksum = pkt.IP.CalculateChecksum()

	// TODO(soypat): Document how to handle ToS. For now just use ToS used by other side.
	// packet.IP.ToS = 0
	pkt.IP.Flags = 0
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

	pkt.Rx = forcedTime // Mark packet as containing data.
	return pkt, nil
}

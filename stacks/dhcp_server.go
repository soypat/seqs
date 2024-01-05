package stacks

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/eth/dhcp"
)

type dhcpclient struct {
	addr        netip.Addr
	state       uint8
	port        uint16
	requestlist [10]byte
}

type DHCPServer struct {
	stack      *PortStack
	nextAddr   netip.Addr
	siaddr     netip.Addr
	port       uint16
	hosts      map[[6]byte]dhcpclient
	aborted    bool
	lastPacket UDPPacket
	hasPacket  bool
}

func NewDHCPServer(ps *PortStack, siaddr netip.Addr, lport uint16) *DHCPServer {
	if ps == nil || lport == 0 {
		panic("nil portstack or local port")
	}
	return &DHCPServer{
		stack:  ps,
		port:   lport,
		siaddr: siaddr,
	}
}

func (d *DHCPServer) Start() error {
	d.hosts = make(map[[6]byte]dhcpclient)
	d.aborted = false
	return d.stack.OpenUDP(d.port, d)
}

func (d *DHCPServer) recv(pkt *UDPPacket) (err error) {
	if d.isAborted() {
		return io.EOF // Signal to close socket.
	}
	if d.hasPacket {
		return ErrDroppedPacket
	}
	d.hasPacket = true
	d.lastPacket = *pkt
	return nil
}

func (d *DHCPServer) send(dst []byte) (int, error) {
	if d.isAborted() {
		return 0, io.EOF // Signal to close socket.
	}
	if !d.hasPacket {
		return 0, nil
	}
	n, err := d.HandleUDP(dst, &d.lastPacket)
	d.hasPacket = false
	return n, err
}

func (d *DHCPServer) isPendingHandling() bool {
	return d.port != 0 && d.hasPacket
}

func (d *DHCPServer) isAborted() bool { return d.aborted }

func (d *DHCPServer) abort() {
	*d = DHCPServer{
		stack:   d.stack,
		siaddr:  d.siaddr,
		port:    d.port,
		hosts:   nil, // TODO: is this wise?
		aborted: true,
	}
}

func (d *DHCPServer) HandleUDP(resp []byte, packet *UDPPacket) (_ int, err error) {
	// First action is used to send data without having received a packet
	// so hasPacket will be false.
	hasPacket := d.hasPacket
	incpayload := packet.Payload()
	switch {
	case len(resp) < dhcp.SizeHeader:
		return 0, errors.New("short payload to marshall DHCP")
	case hasPacket && len(incpayload) < eth.SizeDHCPHeader:
		return 0, errors.New("short payload to parse DHCP")
	case !hasPacket:
		return 0, nil
	}

	rcvHdr := dhcp.DecodeHeaderV4(incpayload)
	mac := packet.Eth.Source
	client := d.hosts[mac]
	var msgType dhcp.MessageType
	err = dhcp.ForEachOption(incpayload, func(opt dhcp.Option) error {
		switch opt.Num {
		case dhcp.OptMessageType:
			if len(opt.Data) == 1 {
				msgType = dhcp.MessageType(opt.Data[0])
			}
		case dhcp.OptParameterRequestList:
			client.requestlist = [10]byte{}
			copy(client.requestlist[:], opt.Data)
		case dhcp.OptRequestedIPaddress:
			if len(opt.Data) == 4 && client.state == dhcpStateNone {
				client.addr = netip.AddrFrom4([4]byte(opt.Data))
			}
		}
		return nil
	})
	if err != nil || (msgType != 1 && rcvHdr.SIAddr != d.siaddr.As4()) {
		return 0, err
	}

	var Options []dhcp.Option
	switch msgType {
	case dhcp.MsgDiscover:
		if client.state != dhcpStateNone {
			err = errors.New("DHCP Discover on initialized client")
			break
		}
		rcvHdr.YIAddr = d.next(client.addr.As4())
		Options = []dhcp.Option{
			{Num: dhcp.OptMessageType, Data: []byte{byte(dhcp.MsgOffer)}},
		}
		rcvHdr.SIAddr = d.siaddr.As4()
		client.port = packet.UDP.SourcePort
		client.state = dhcpStateWaitOffer

	case dhcp.MsgRequest:
		if client.state != dhcpStateWaitOffer {
			err = errors.New("unexpected DHCP Request")
			break
		}
		Options = []dhcp.Option{
			{Num: dhcp.OptMessageType, Data: []byte{byte(dhcp.MsgAck)}}, // DHCP Message Type: ACK
		}
	}
	if err != nil {
		return 0, nil
	}
	d.hosts[mac] = client
	const dhcpOffset = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
	for i := dhcpOffset + 14; i < len(resp); i++ {
		resp[i] = 0 // Zero out BOOTP and options fields.
	}
	rcvHdr.Put(resp[dhcpOffset:])
	// Encode DHCP header + options.
	const magicCookie = 0x63825363
	ptr := dhcpOffset + dhcp.MagicCookieOffset
	binary.BigEndian.PutUint32(resp[ptr:], magicCookie)
	ptr = dhcpOffset + dhcp.OptionsOffset
	for _, opt := range Options {
		n, err := opt.Encode(resp[ptr:])
		if err != nil {
			return n, err
		}
		ptr += n
	}
	resp[ptr] = 0xff // endmark
	ptr++
	// Set Ethernet+IP+UDP headers.
	payload := resp[dhcpOffset:ptr]
	d.setResponseUDP(client.port, packet, payload)
	packet.PutHeaders(resp)
	return ptr, nil
}

func (d *DHCPServer) next(requested [4]byte) [4]byte {
	if requested != [4]byte{} {
		return requested
	}
	return [4]byte{192, 168, 1, 2}
}

func (d *DHCPServer) setResponseUDP(clientport uint16, packet *UDPPacket, payload []byte) {
	const ipLenInWords = 5
	// Ethernet frame.
	packet.Eth.Destination = eth.BroadcastHW6()
	packet.Eth.Source = d.stack.HardwareAddr6()

	packet.Eth.SizeOrEtherType = uint16(eth.EtherTypeIPv4)

	// IPv4 frame.
	packet.IP.Destination = [4]byte{}
	packet.IP.Source = d.siaddr.As4() // Source IP is always zeroed when client sends.
	packet.IP.Protocol = 17           // UDP
	packet.IP.TTL = 64
	packet.IP.ID = prand16(packet.IP.ID)
	packet.IP.VersionAndIHL = ipLenInWords // Sets IHL: No IP options. Version set automatically.
	packet.IP.TotalLength = 4*ipLenInWords + eth.SizeUDPHeader + uint16(len(payload))
	packet.IP.Checksum = packet.IP.CalculateChecksum()
	// TODO(soypat): Document why disabling ToS used by DHCP server may cause Request to fail.
	// Apparently server sets ToS=192. Uncommenting this line causes DHCP to fail on my setup.
	// If left fixed at 192, DHCP does not work.
	// If left fixed at 0, DHCP does not work.
	// Apparently ToS is a function of which state of DHCP one is in. Not sure why code below works.
	packet.IP.ToS = 192
	packet.IP.Flags = 0

	// UDP frame.
	packet.UDP.DestinationPort = clientport
	packet.UDP.SourcePort = d.port
	packet.UDP.Length = packet.IP.TotalLength - 4*ipLenInWords
	packet.UDP.Checksum = packet.UDP.CalculateChecksumIPv4(&packet.IP, payload)
}

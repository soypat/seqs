package stacks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/eth/dhcp"
)

type DHCPClient struct {
	stack *PortStack
	state uint8
	// The result IP of the DHCP transaction (our new IP).
	offer [4]byte
	// DHCP server IP
	svip        [4]byte
	requestedIP [4]byte
	currentXid  uint32
	port        uint16
	aborted     bool
	aux         UDPPacket // Avoid heap allocation.
}

// State transition table:
//
//	StateNone      -> | Send out Discover | -> StateWaitOffer
//	StateWaitOffer -> |   Receive Offer   | -> StateGotOffer
//	StateGotOffer  -> | Send out Request  | -> StateWaitAck
//	StateWaitAck   -> |    Receive Ack    | -> StateDone
const (
	dhcpStateNone = iota
	dhcpStateWaitOffer
	dhcpStateGotOffer
	dhcpStateWaitAck
	dhcpStateDone
)

func NewDHCPClient(stack *PortStack, lport uint16) *DHCPClient {
	if stack == nil || lport == 0 {
		panic("nil stack or port")
	}
	return &DHCPClient{
		stack: stack,
		state: dhcpStateNone,
		port:  lport,
	}
}

type DHCPRequestConfig struct {
	RequestedAddr netip.Addr
	Xid           uint32
}

func (d *DHCPClient) BeginRequest(cfg DHCPRequestConfig) error {
	if cfg.Xid == 0 {
		return errors.New("xid must be non-zero")
	} else if !cfg.RequestedAddr.Is4() {
		return errors.New("requested addr must be IPv4")
	}
	d.currentXid = cfg.Xid
	d.requestedIP = cfg.RequestedAddr.As4()
	d.state = dhcpStateNone
	err := d.stack.OpenUDP(d.port, d)
	if err != nil {
		return err
	}
	return d.stack.FlagPendingUDP(d.port)
}

func (d *DHCPClient) Done() bool {
	return d.state == dhcpStateDone
}

func (d *DHCPClient) Offer() netip.Addr {
	return netip.AddrFrom4(d.offer)
}

func (d *DHCPClient) ourHeader() dhcp.HeaderV4 {
	hdr := dhcp.HeaderV4{
		OP:     dhcp.OpRequest,
		Xid:    d.currentXid,
		HType:  1,
		HLen:   6,
		HOps:   0,
		CIAddr: d.stack.Addr().As4(),
		SIAddr: d.svip,
		YIAddr: d.offer,
	}
	mac := d.stack.MACAs6()
	copy(hdr.CHAddr[:], mac[:])
	return hdr
}

func (d *DHCPClient) isAborted() bool { return d.currentXid == 0 || d.aborted }

func (d *DHCPClient) send(dst []byte) (n int, err error) {
	if !d.isPendingHandling() {
		return 0, io.EOF // Signal to close socket.
	}
	const dhcpOffset = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
	switch {
	case len(dst) < dhcpOffset+dhcp.SizeDatagram:
		return 0, errors.New("short payload to marshall DHCP")
	}

	// Switch statement prepares DHCP response depending on whether we're waiting
	// for offer, ack or if we still need to send a discover (StateNone).
	var Options []dhcp.Option
	var nextstate uint8
	switch d.state { // Send.
	case dhcpStateNone:
		// DHCP options.
		Options = []dhcp.Option{
			{Num: dhcp.OptMessageType, Data: []byte{byte(dhcp.MsgDiscover)}},
			{Num: dhcp.OptParameterRequestList, Data: []byte{1, 3, 15, 6}},
		}
		if d.requestedIP != [4]byte{} {
			Options = append(Options, dhcp.Option{Num: dhcp.OptRequestedIPaddress, Data: d.requestedIP[:]})
		}
		nextstate = dhcpStateWaitOffer

	case dhcpStateGotOffer:
		// Accept this server's offer.
		Options = []dhcp.Option{
			{Num: dhcp.OptMessageType, Data: []byte{byte(dhcp.MsgRequest)}},
			{Num: dhcp.OptRequestedIPaddress, Data: d.offer[:]},
			{Num: dhcp.OptServerIdentification, Data: d.svip[:]},
		}
		nextstate = dhcpStateWaitAck

	default:
		err = fmt.Errorf("UNHANDLED CASE %v", d.state)
	}
	if err != nil {
		return 0, nil
	}

	for i := dhcpOffset + 14; i < len(dst); i++ {
		dst[i] = 0 // Zero out BOOTP and options fields.
	}

	// Encode DHCP header + options.
	const magicCookie = 0x63825363
	outgoingHdr := d.ourHeader()
	outgoingHdr.Put(dst[dhcpOffset:])

	ptr := dhcpOffset + dhcp.MagicCookieOffset
	binary.BigEndian.PutUint32(dst[ptr:], magicCookie)
	ptr = dhcpOffset + dhcp.OptionsOffset
	for _, opt := range Options {
		n, err = opt.Encode(dst[ptr:])
		if err != nil {
			return 0, err
		}
		ptr += n
	}
	dst[ptr] = 0xff // endmark
	// Set Ethernet+IP+UDP headers.
	payload := dst[dhcpOffset : dhcpOffset+dhcp.SizeDatagram]
	pkt := &d.aux
	d.setResponseUDP(pkt, payload)
	pkt.PutHeaders(dst)
	d.state = nextstate
	return dhcpOffset + dhcp.SizeDatagram, nil
}

func (d *DHCPClient) recv(pkt *UDPPacket) (err error) {
	if !d.isPendingHandling() {
		return io.EOF // Signal to close socket.
	}

	incpayload := pkt.Payload()
	if len(incpayload) < dhcp.SizeHeader {
		return errors.New("short payload to parse DHCP")
	}

	rcvHdr := dhcp.DecodeHeaderV4(incpayload)
	if rcvHdr.Xid != d.currentXid {
		return errors.New("dhcp-rx: unexpected xid")
	}

	// Parse DHCP options looking for message type field.
	var msgType dhcp.MessageType
	err = dhcp.ForEachOption(incpayload, func(opt dhcp.Option) error {
		switch opt.Num {
		case dhcp.OptMessageType:
			if len(opt.Data) == 1 {
				msgType = dhcp.MessageType(opt.Data[0])
			}
		}
		return nil
	})

	d.stack.debug("dhcp-rx", slog.Uint64("msgtype", uint64(msgType)))
	switch d.state { // Receive.
	case dhcpStateWaitOffer:
		// Accept this server's offer.
		d.svip = rcvHdr.SIAddr
		d.offer = rcvHdr.YIAddr
		d.state = dhcpStateGotOffer
	case dhcpStateWaitAck:
		if msgType == dhcp.MsgAck {
			d.state = dhcpStateDone
		}
	case dhcpStateDone:
		err = io.EOF // We got a valid response, close socket.
	default:
		err = errors.New("unhandled dhcp-rx case: " + strconv.Itoa(int(d.state)))
	}
	if err != nil {
		return err
	}
	return nil
}

func (d *DHCPClient) isPendingHandling() bool {
	return !d.isAborted() && d.state != dhcpStateDone
}

func (d *DHCPClient) Abort() {
	d.aborted = true
}

func (d *DHCPClient) abort() {
	*d = DHCPClient{
		stack: d.stack,
		port:  d.port,
	}
}

/*
func (d *DHCPv4Client) HandleUDP(resp []byte, packet *UDPPacket) (_ int, err error) {
	const (
		xid = 0x12345678

		sizeSName     = 64  // Server name, part of BOOTP too.
		sizeFILE      = 128 // Boot file name, Legacy.
		sizeOptions   = 312
		dhcpOffset    = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
		optionsStart  = dhcpOffset + eth.SizeDHCPHeader + sizeSName + sizeFILE
		sizeDHCPTotal = eth.SizeDHCPHeader + sizeSName + sizeFILE + sizeOptions
	)
	// First action is used to send data without having received a packet
	// so hasPacket will be false.
	hasPacket := packet.HasPacket()
	incpayload := packet.Payload()
	switch {
	case len(resp) < sizeDHCPTotal:
		return 0, errors.New("short payload to marshall DHCP")
	case hasPacket && len(incpayload) < eth.SizeDHCPHeader:
		return 0, errors.New("short payload to parse DHCP")
	}

	var rcvHdr eth.DHCPHeader
	if hasPacket {
		rcvHdr = eth.DecodeDHCPHeader(incpayload)
		// Parse DHCP options.
		ptr := eth.SizeDHCPHeader + sizeSName + sizeFILE + 4
		for ptr+1 < len(incpayload) && int(incpayload[ptr+1]) < len(incpayload) {
			if incpayload[ptr] == 0xff {
				break
			}
			option := eth.DHCPOption(incpayload[ptr])
			optlen := incpayload[ptr+1]
			optionData := incpayload[ptr+2 : ptr+2+int(optlen)]
			if d.state == dhcpStateWaitAck && option == eth.DHCP_MessageType && len(optionData) > 0 && optionData[0] == 5 {
				d.state = dhcpStateDone
				return 0, nil
			}
			ptr += int(optlen) + 2
		}
	}

	// Switch statement prepares DHCP response depending on whether we're waiting
	// for offer, ack or if we still need to send a discover (StateNone).
	var Options []dhcpOption
	switch {
	case !hasPacket && d.state == dhcpStateNone:
		d.initOurHeader(xid)
		// DHCP options.
		Options = []dhcpOption{
			{53, []byte{1}},           // DHCP Message Type: Discover
			{55, []byte{1, 3, 15, 6}}, // Parameter request list
		}
		if d.RequestedIP != [4]byte{} {
			Options = append(Options, dhcpOption{50, d.RequestedIP[:]})
		}
		d.state = dhcpStateWaitOffer

	case hasPacket && d.state == dhcpStateWaitOffer:
		offer := net.IP(rcvHdr.YIAddr[:])
		Options = []dhcpOption{
			{53, []byte{3}},        // DHCP Message Type: Request
			{50, offer},            // Requested IP
			{54, rcvHdr.SIAddr[:]}, // DHCP server IP
		}
		// Accept this server's offer.
		copy(d.ourHeader.SIAddr[:], rcvHdr.SIAddr[:])
		copy(d.offer[:], offer) // Store our new IP.
		d.state = dhcpStateWaitAck
	default:
		err = fmt.Errorf("UNHANDLED CASE %v %+v", hasPacket, d)
	}
	if err != nil {
		return 0, nil
	}
	for i := dhcpOffset + 14; i < len(resp); i++ {
		resp[i] = 0 // Zero out BOOTP and options fields.
	}
	// Encode DHCP header + options.
	const magicCookie = 0x63825363
	d.ourHeader.Put(resp[dhcpOffset:])
	ptr := optionsStart
	binary.BigEndian.PutUint32(resp[ptr:], magicCookie)
	ptr += 4
	for _, opt := range Options {
		ptr += encodeDHCPOption(resp[ptr:], opt)
	}
	resp[ptr] = 0xff // endmark
	// Set Ethernet+IP+UDP headers.
	payload := resp[dhcpOffset : dhcpOffset+sizeDHCPTotal]
	d.setResponseUDP(packet, payload)
	packet.PutHeaders(resp)
	return dhcpOffset + sizeDHCPTotal, nil
}
*/

func (d *DHCPClient) setResponseUDP(packet *UDPPacket, payload []byte) {
	const ipLenInWords = 5
	// Ethernet frame.
	broadcast := eth.BroadcastHW6()
	packet.Eth.Destination = broadcast
	packet.Eth.Source = d.stack.MACAs6()
	packet.Eth.SizeOrEtherType = uint16(eth.EtherTypeIPv4)

	// IPv4 frame.
	packet.IP.Destination = [4]byte(broadcast[:4])
	packet.IP.Source = packet.IP.Destination

	packet.IP.Source = [4]byte{} // Source IP is always zeroed when client sends.
	packet.IP.Protocol = 17      // UDP
	packet.IP.TTL = 64
	packet.IP.ID = prand16(packet.IP.ID)
	packet.IP.VersionAndIHL = ipLenInWords // Sets IHL: No IP options. Version set automatically.
	packet.IP.TotalLength = 4*ipLenInWords + eth.SizeUDPHeader + uint16(len(payload))
	// TODO(soypat): Document why disabling ToS used by DHCP server may cause Request to fail.
	// Apparently server sets ToS=192. Uncommenting this line causes DHCP to fail on my setup.
	// If left fixed at 192, DHCP does not work.
	// If left fixed at 0, DHCP does not work.
	// Apparently ToS is a function of which state of DHCP one is in. Not sure why code below works.
	if d.state <= dhcpStateWaitOffer {
		packet.IP.ToS = 0
	} else {
		packet.IP.ToS = 192
	}
	packet.IP.Flags = 0
	packet.IP.Checksum = packet.IP.CalculateChecksum()
	// UDP frame.
	packet.UDP.DestinationPort = 67
	packet.UDP.SourcePort = 68
	packet.UDP.Length = packet.IP.TotalLength - 4*ipLenInWords
	packet.UDP.Checksum = packet.UDP.CalculateChecksumIPv4(&packet.IP, payload)
}

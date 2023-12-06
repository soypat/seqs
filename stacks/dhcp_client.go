package stacks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/soypat/seqs/eth"
)

type DHCPv4Client struct {
	ourHeader eth.DHCPHeader
	state     uint8
	MAC       [6]byte
	// The result IP of the DHCP transaction (our new IP).
	YourIP [4]byte
	// DHCP server IP
	ServerIP    [4]byte
	RequestedIP [4]byte
}

const (
	dhcpStateNone = iota
	dhcpStateWaitOffer
	dhcpStateWaitAck
	dhcpStateDone
)

func (d *DHCPv4Client) Done() bool {
	return d.state == dhcpStateDone
}

// Reset resets the DHCP client to its initial state and discards all state.
// After being reset the client will try to obtain a new IP address if it is attached to a PortStack.
func (d *DHCPv4Client) Reset() {
	d.abort()
}

func (d *DHCPv4Client) isAborted() bool { return d.MAC == [6]byte{} }

func (d *DHCPv4Client) send(dst []byte) (n int, err error) {
	if d.state == dhcpStateDone || d.isAborted() {
		return 0, io.EOF // Signal to close socket.
	}
	// Send DHCP request.
	return d.HandleUDP(dst, nil)
}

func (d *DHCPv4Client) recv(pkt *UDPPacket) error {
	if d.state == dhcpStateDone || d.isAborted() {
		return io.EOF // Signal to close socket.
	}
	// Receive DHCP response.
	_, err := d.HandleUDP(nil, pkt)
	return err
}

func (d *DHCPv4Client) isPendingHandling() bool {
	return d.state != dhcpStateDone
}

func (d *DHCPv4Client) abort() {
	*d = DHCPv4Client{
		MAC:         d.MAC,
		RequestedIP: d.RequestedIP,
	}
}

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
		copy(d.YourIP[:], offer) // Store our new IP.
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

// initOurHeader zero's out most of header and sets the xid and MAC address along with OP=1.
func (d *DHCPv4Client) initOurHeader(xid uint32) {
	dhdr := &d.ourHeader
	dhdr.OP = 1
	dhdr.HType = 1
	dhdr.HLen = 6
	dhdr.HOps = 0
	dhdr.Secs = 0
	dhdr.Flags = 0
	dhdr.Xid = xid
	dhdr.CIAddr = [4]byte{}
	dhdr.YIAddr = [4]byte{}
	dhdr.SIAddr = [4]byte{}
	dhdr.GIAddr = [4]byte{}
	copy(dhdr.CHAddr[:], d.MAC[:])
}

func (d *DHCPv4Client) setResponseUDP(packet *UDPPacket, payload []byte) {
	const ipLenInWords = 5
	// Ethernet frame.
	broadcast := eth.BroadcastHW6()
	packet.Eth.Destination = broadcast
	copy(packet.Eth.Source[:], d.MAC[:])
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
	packet.IP.Checksum = packet.IP.CalculateChecksum()
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

	// UDP frame.
	packet.UDP.DestinationPort = 67
	packet.UDP.SourcePort = 68
	packet.UDP.Length = packet.IP.TotalLength - 4*ipLenInWords
	packet.UDP.Checksum = packet.UDP.CalculateChecksumIPv4(&packet.IP, payload)
}

func encodeDHCPOption(dst []byte, opt dhcpOption) int {
	if len(opt.Data)+2 > len(dst) {
		panic("small dst size for DHCP encoding")
	}
	dst[0] = byte(opt.Opt)
	dst[1] = byte(len(opt.Data))
	copy(dst[2:], opt.Data)
	return 2 + len(opt.Data)
}

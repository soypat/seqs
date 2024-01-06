package stacks

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/bits"
	"net/netip"
	"strconv"
	"time"
	"unsafe"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/eth/dhcp"
	"github.com/soypat/seqs/internal"
)

var (
	undefinedIPv4 = netip.AddrFrom4([4]byte{})
	broadcastIPv4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)
var (
	errUnhandledState = errors.New("unhandled state")
	errBadMagicCookie = errors.New("bad magic cookie")
	errUnexpectedXid  = errors.New("unexpected xid")
)

type DHCPClient struct {
	stack           *PortStack
	currentXid      uint32
	port            uint16
	requestHostname string
	aux             UDPPacket // Avoid heap allocation.
	// aborted         bool
	state uint8
	// The result IP of the DHCP transaction (our new IP).
	offer [4]byte
	// DHCP server IP
	svip        [4]byte
	requestedIP [4]byte
	dns         [4]byte
	router      [4]byte
	subnet      [4]byte
	broadcast   [4]byte
	gateway     [4]byte
	optionbuf   [10]dhcp.Option
	hostname    []byte
	tRenew      uint32 // Opt(58): Renewal time [s]
	tRebind     uint32 // Opt(59): Rebinding time [s]
	tIPLease    uint32 // Opt(51): IP lease time [s]
	// This field is for avoiding heap allocations.
	auxbuf [4]byte
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
	dhcpStateAborted
	dhcpStateNaked
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
	// Optional hostname to request.
	Hostname string
	ServerIP netip.Addr
}

func (d *DHCPClient) BeginRequest(cfg DHCPRequestConfig) error {
	if cfg.Xid == 0 {
		return errors.New("xid must be non-zero")
	} else if cfg.RequestedAddr.IsValid() && !cfg.RequestedAddr.Is4() {
		return errors.New("requested addr must be IPv4")
	} else if len(cfg.Hostname) > 30 {
		return errors.New("hostname too long")
	} else if cfg.ServerIP.IsValid() && !cfg.ServerIP.Is4() {
		return errors.New("server IP must be IPv4")
	} else if d.state != dhcpStateNone {
		return errors.New("already started, call Abort() first")
	}

	err := d.stack.OpenUDP(d.port, d)
	if err != nil {
		return err
	}
	d.currentXid = cfg.Xid
	if cfg.RequestedAddr.IsValid() {
		d.requestedIP = cfg.RequestedAddr.As4()
	}
	if !cfg.ServerIP.IsValid() {
		// Default is to use broadcast.
		cfg.ServerIP = broadcastIPv4
	}
	d.svip = cfg.ServerIP.As4()
	d.state = dhcpStateNone
	d.requestHostname = cfg.Hostname
	return d.stack.FlagPendingUDP(d.port)
}

func (d *DHCPClient) IsDone() bool {
	return d.state == dhcpStateDone || d.state == dhcpStateNaked
}

// DHCPServer IP address field of the DHCP packet. Is the siaddr field of the DHCP packet, which can be overriden with the Server IP option.
func (d *DHCPClient) DHCPServer() netip.Addr {
	return ipv4orInvalid(d.svip)
}

// Gateway IP address field of the DHCP packet. The giaddr provides the DHCP server with information about the IP address subnet in which the client resides.
func (d *DHCPClient) Gateway() netip.Addr {
	return ipv4orInvalid(d.gateway)
}

func (d *DHCPClient) DNSServer() netip.Addr {
	return ipv4orInvalid(d.dns)
}

func (d *DHCPClient) Offer() netip.Addr {
	return ipv4orInvalid(d.offer)
}

func (d *DHCPClient) Hostname() []byte {
	return d.hostname
}

func (d *DHCPClient) Router() netip.Addr {
	return ipv4orInvalid(d.router)
}

func (d *DHCPClient) BroadcastAddr() netip.Addr {
	return ipv4orInvalid(d.broadcast)
}

func (d *DHCPClient) RebindingTime() time.Duration {
	return time.Duration(d.tRebind) * time.Second
}
func (d *DHCPClient) RenewalTime() time.Duration {
	return time.Duration(d.tRenew) * time.Second
}
func (d *DHCPClient) IPLeaseTime() time.Duration {
	return time.Duration(d.tIPLease) * time.Second
}

func (d *DHCPClient) CIDRBits() uint8 {
	if d.subnet == [4]byte{} {
		return 0
	}
	v := binary.BigEndian.Uint32(d.subnet[:])
	return 32 - uint8(bits.TrailingZeros32(v))
}

// func (d *DHCPClient) SubnetMask() netip.Prefix {
// 	return netip.PrefixFrom4(d.subnet)
// }

func (d *DHCPClient) ourHeader() dhcp.HeaderV4 {
	hdr := dhcp.HeaderV4{
		OP:     dhcp.OpRequest,
		Xid:    d.currentXid,
		HType:  1,
		HLen:   6,
		HOps:   0,
		Secs:   1,
		CIAddr: d.stack.Addr().As4(),
		SIAddr: d.svip,
		YIAddr: d.offer,
	}
	mac := d.stack.HardwareAddr6()
	copy(hdr.CHAddr[:], mac[:])
	return hdr
}

func (d *DHCPClient) isAborted() bool { return d.state == dhcpStateAborted }

var dhcpDefaultParamReqList = []dhcp.OptNum{
	dhcp.OptSubnetMask,
	dhcp.OptTimeOffset,
	dhcp.OptRouter,
	dhcp.OptInterfaceMTUSize,
	dhcp.OptBroadcastAddress,
	dhcp.OptDNSServers,
	dhcp.OptDomainName,
	dhcp.OptNTPServersAddresses,
}

func getDefaultParams() []byte {
	ptr := unsafe.SliceData(dhcpDefaultParamReqList)
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(dhcpDefaultParamReqList))
}

func (d *DHCPClient) send(dst []byte) (n int, err error) {
	if d.isAborted() {
		return 0, io.EOF
	} else if !d.isPendingHandling() {
		return 0, nil
	}
	const dhcpOffset = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
	switch {
	case len(dst) < dhcpOffset+dhcp.OptionsOffset+128:
		return 0, io.ErrShortBuffer
	}

	// Switch statement prepares DHCP response depending on whether we're waiting
	// for offer, ack or if we still need to send a discover (StateNone).
	var Options []dhcp.Option
	var nextstate uint8
	switch d.state { // Send.
	case dhcpStateNone:
		// Supposing no IP options:
		maxDHCPSize := d.stack.MTU() - eth.SizeEthernetHeader - eth.SizeIPv4Header - eth.SizeUDPHeader
		// DHCP options.
		d.auxbuf[0] = byte(dhcp.MsgDiscover)
		binary.BigEndian.PutUint16(d.auxbuf[1:3], maxDHCPSize)
		Options = append(d.optionbuf[:0], []dhcp.Option{
			{Num: dhcp.OptMessageType, Data: d.auxbuf[:1]},
			{Num: dhcp.OptParameterRequestList, Data: getDefaultParams()},
			{Num: dhcp.OptClientIdentifier, Data: d.stack.mac[:]},
			{Num: dhcp.OptMaximumMessageSize, Data: d.auxbuf[1:3]},
		}...)
		if d.requestedIP != [4]byte{} {
			Options = append(Options, dhcp.Option{Num: dhcp.OptRequestedIPaddress, Data: d.requestedIP[:]})
		}
		nextstate = dhcpStateWaitOffer

	case dhcpStateGotOffer:
		d.auxbuf[0] = byte(dhcp.MsgRequest)
		// Accept this server's offer.
		Options = append(d.optionbuf[:0], []dhcp.Option{
			{Num: dhcp.OptMessageType, Data: d.auxbuf[:1]},
			{Num: dhcp.OptRequestedIPaddress, Data: d.offer[:]},
			{Num: dhcp.OptServerIdentification, Data: d.svip[:]},
		}...)
		nextstate = dhcpStateWaitAck

	default:
		err = errUnhandledState
	}
	if err != nil {
		return 0, nil
	}
	if d.requestHostname != "" {
		Options = append(Options, dhcp.Option{Num: dhcp.OptHostName, Data: unsafe.Slice(unsafe.StringData(d.requestHostname), len(d.requestHostname))})
	}
	for i := dhcpOffset + 14; i < len(dst); i++ {
		dst[i] = 0 // Zero out BOOTP and options fields.
	}

	// Encode DHCP header + options.
	outgoingHdr := d.ourHeader()
	outgoingHdr.Put(dst[dhcpOffset:])

	ptr := dhcpOffset + dhcp.MagicCookieOffset
	binary.BigEndian.PutUint32(dst[ptr:], dhcp.MagicCookie)
	ptr = dhcpOffset + dhcp.OptionsOffset
	for _, opt := range Options {
		n, err = opt.Encode(dst[ptr:])
		if err != nil {
			return 0, err
		}
		ptr += n
	}
	dst[ptr] = 0xff // endmark
	ptr++
	// Set Ethernet+IP+UDP headers.
	payload := dst[dhcpOffset:ptr]
	pkt := &d.aux
	// TODO(soypat): Document why disabling ToS used by DHCP server may cause Request to fail.
	// Apparently server sets ToS=192. Uncommenting this line causes DHCP to fail on my setup.
	// If left fixed at 192, DHCP does not work.
	// If left fixed at 0, DHCP does not work.
	// Apparently ToS is a function of which state of DHCP one is in. Not sure why code below works.
	// Note: Not exactly needed for all servers.
	var ToS uint8
	if d.state > dhcpStateWaitOffer {
		ToS = 192
	}
	broadcast := eth.BroadcastHW6()
	setUDP(pkt, d.stack.mac, broadcast, d.stack.ip, broadcastIPv4.As4(), ToS, payload, 68, 67)
	pkt.PutHeaders(dst)
	d.state = nextstate
	if d.stack.isLogEnabled(slog.LevelInfo) {
		d.stack.info("DHCP:tx", slog.String("msg", dhcp.MessageType(Options[0].Data[0]).String()))
	}
	return ptr, nil
}

func (d *DHCPClient) recv(pkt *UDPPacket) (err error) {
	if d.isAborted() {
		return io.EOF
	}
	incpayload := pkt.Payload()
	if len(incpayload) < dhcp.SizeHeader {
		return io.ErrShortBuffer
	}

	rcvHdr := dhcp.DecodeHeaderV4(incpayload)
	if rcvHdr.Xid != d.currentXid {
		return errUnexpectedXid
	}

	cookie := binary.BigEndian.Uint32(incpayload[dhcp.MagicCookieOffset:])
	if cookie != dhcp.MagicCookie {
		return errBadMagicCookie
	}

	// Parse DHCP options looking for message type field.
	// var mt dhcp.MessageType
	mt := &d.auxbuf[0]
	db := &d.auxbuf[1]
	*db = 0
	if d.stack.isLogEnabled(slog.LevelDebug) {
		*db = 1
	}
	if d.state == dhcpStateWaitOffer {
		d.svip = rcvHdr.SIAddr
	}
	err = dhcp.ForEachOption(incpayload, func(opt dhcp.Option) error {
		switch opt.Num {
		case dhcp.OptMessageType:
			if len(opt.Data) == 1 {
				*mt = opt.Data[0]
			}
		// The DHCP server information does not have to be in the header, but can
		// be in the options. Copy into the decoded header for simplicity.
		case dhcp.OptServerIdentification:
			d.svip = maybeIP(opt.Data)
		case dhcp.OptDNSServers:
			d.dns = maybeIP(opt.Data)
		case dhcp.OptRouter:
			d.router = maybeIP(opt.Data)
		case dhcp.OptSubnetMask:
			d.subnet = maybeIP(opt.Data)
		case dhcp.OptBroadcastAddress:
			d.broadcast = maybeIP(opt.Data)
		case dhcp.OptHostName:
			// Avoid heavy heap allocations, especially if hostname not requested.
			if len(d.hostname) < 16 || len(d.hostname) <= len(d.requestHostname) {
				d.hostname = append(d.hostname[:0], opt.Data...)
			}
		case dhcp.OptRenewTimeValue:
			d.tRenew = maybeU32(opt.Data)
		case dhcp.OptIPAddressLeaseTime:
			d.tIPLease = maybeU32(opt.Data)
		case dhcp.OptRebindingTimeValue:
			d.tRebind = maybeU32(opt.Data)
		}
		if *db != 0 && !internal.HeapAllocDebugging {
			d.stack.debug("DHCP:rx", slog.String("opt", opt.Num.String()), slog.String("data", stringNumList(opt.Data)))
		}
		return nil
	})

	msgType := dhcp.MessageType(*mt)
	if d.stack.isLogEnabled(slog.LevelInfo) {
		d.stack.info("DHCP:rx", slog.String("msg", msgType.String()))
	}
	switch d.state { // Receive.
	case dhcpStateWaitOffer:
		// Accept this server's offer.
		d.gateway = rcvHdr.GIAddr
		d.offer = rcvHdr.YIAddr
		d.state = dhcpStateGotOffer
	case dhcpStateWaitAck:
		if msgType == dhcp.MsgAck {
			d.state = dhcpStateDone
		} else if msgType == dhcp.MsgNak {
			d.state = dhcpStateNaked
		}
	case dhcpStateDone:
		err = io.EOF // We got a valid response, close socket.
	default:
		err = errUnhandledState
	}
	if err != nil {
		return err
	}
	return nil
}

func (d *DHCPClient) isPendingHandling() bool {
	return d.isAborted() || d.state == dhcpStateNone || d.state == dhcpStateGotOffer
}

func (d *DHCPClient) Abort() {
	d.state = dhcpStateAborted
}

func (d *DHCPClient) abort() {
	*d = DHCPClient{
		stack: d.stack,
		port:  d.port,
	}
}

func setUDP(packet *UDPPacket, srcHW, dstHW [6]byte, srcAddr, dstAddr [4]byte, ipTOS uint8, payload []byte, lport, rport uint16) {
	const ipLenInWords = 5
	// Ethernet frame.
	packet.Eth = eth.EthernetHeader{
		Destination:     dstHW,
		Source:          srcHW,
		SizeOrEtherType: uint16(eth.EtherTypeIPv4),
	}

	// IPv4 frame.
	packet.IP = eth.IPv4Header{
		Source:        srcAddr,
		Destination:   dstAddr,
		VersionAndIHL: ipLenInWords, // Sets IHL: No IP options. Version set automatically.
		TotalLength:   4*ipLenInWords + eth.SizeUDPHeader + uint16(len(payload)),
		Protocol:      17, // UDP
		TTL:           64,
		ID:            prand16(packet.IP.ID),
		ToS:           ipTOS,
		Flags:         0x40 << 8, // Don't fragment.
	}
	packet.IP.Checksum = packet.IP.CalculateChecksum()
	// UDP frame.
	packet.UDP = eth.UDPHeader{
		SourcePort:      lport,
		DestinationPort: rport,
		Length:          packet.IP.TotalLength - 4*ipLenInWords,
	}
	packet.UDP.Checksum = packet.UDP.CalculateChecksumIPv4(&packet.IP, payload)
}

func dhcpStringify(udpPayload []byte) string {
	var (
		dhdr = dhcp.DecodeHeaderV4(udpPayload)
		s    = dhdr.String()
	)
	dhcp.ForEachOption(udpPayload, func(opt dhcp.Option) error {
		s += " " + opt.String()
		return nil
	})
	return s
}

func stringNumList(data []byte) string {
	buf := make([]byte, 0, len(data)*2)
	for i, b := range data {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = strconv.AppendUint(buf, uint64(b), 10)
	}
	return unsafe.String(&buf[0], len(buf))
}

func ipv4orInvalid(ipv4 [4]byte) netip.Addr {
	if ipv4 == [4]byte{} {
		return netip.Addr{}
	}
	return netip.AddrFrom4(ipv4)
}

func maybeU32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func maybeIP(b []byte) [4]byte {
	if len(b) != 4 {
		return [4]byte{}
	}
	return [4]byte(b)
}

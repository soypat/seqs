package stack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/soypat/seqs/eth"
)

const (
	_MTU      = 1500
	arpOpWait = 0xffff
)

type PortStackConfig struct {
	MAC [6]byte
	// IP              netip.Addr
	MaxOpenPortsUDP int
	MaxOpenPortsTCP int
	Logger          *slog.Logger
}

// NewPortStack creates a ready to use TCP/UDP Stack instance.
func NewPortStack(cfg PortStackConfig) *PortStack {
	var s PortStack
	s.mac = cfg.MAC
	// s.ip = cfg.IP.As4()
	s.portsUDP = make([]udpPort, cfg.MaxOpenPortsUDP)
	s.portsTCP = make([]tcpPort, cfg.MaxOpenPortsTCP)
	s.logger = cfg.Logger
	return &s
}

var ErrFlagPending = io.ErrNoProgress

// PortStack implements partial TCP/UDP packet muxing to respective sockets with [PortStack.RcvEth].
// This implementation limits itself basic header validation and port matching.
// Users of PortStack are expected to implement connection state, packet buffering and retransmission logic.
//   - In the case of TCP this means implementing the TCP state machine.
//   - In the case of UDP PortStack should be enough to build  most applications.
//
// # Notes on PortStack handlers
//
//   - While PortStack.HandleEth has yet to find a outgoing packet it will look for
//     a port that has a pending packet or has been flagged as pending and call its handler.
//
//   - A call to a handler may or may not have an incoming packet ready to process.
//     When pkt.HasPacket() returns true then pkt contains an incoming packet to the port.
//
//   - When pkt.HasPacket() returns false the contents are undefined.
//
//   - Users can safely use pkt even if pkt.HasPacket() returns false.
//
//   - If the handler returns an error that is not ErrFlagPending then the port
//     is immediately closed and written data is discarded.
//
//   - ErrFlagPending: When returned by the handler then the port is flagged as
//     pending and the written data is handled normally if there is any. If no data is written
//     the call to HandleEth proceeds looking for another port to handle.
//
//   - ErrFlagPending: When returned by the handler then for UDP/TCP implementations the
//     incoming packet argument `pkt` is flagged as not present in future calls to the handler in pkt.HasPacket calls.
//     The handler however can be aware of this fact and still use the pkt argument since the header+payload contents
//     are not modified by the stack.
type PortStack struct {
	lastRx        time.Time
	lastRxSuccess time.Time
	lastTx        time.Time
	mac           [6]byte
	// Set ip to non-nil to ignore packets not meant for us.
	ip               [4]byte
	portsUDP         []udpPort
	portsTCP         []tcpPort
	glob             func([]byte)
	pendingUDPv4     uint32
	pendingTCPv4     uint32
	droppedPackets   uint32
	processedPackets uint32
	// pending ARP reply that must be sent out.
	pendingARPresponse eth.ARPv4Header
	ARPresult          eth.ARPv4Header
	logger             *slog.Logger
}

// Common errors.
var (
	ErrDroppedPacket    = errors.New("dropped packet")
	errPacketExceedsMTU = errors.New("packet exceeds MTU")
	errNotIPv4          = errors.New("require IPv4")
	errPacketSmol       = errors.New("packet too small")
	errTooShortTCPOrUDP = errors.New("packet too short to be TCP/UDP")
	errZeroPort         = errors.New("zero port in TCP/UDP")
	errBadTCPOffset     = errors.New("invalid TCP offset")
	errNilHandler       = errors.New("nil handler")
	errChecksumTCPorUDP = errors.New("invalid TCP/UDP checksum")
	errBadUDPLength     = errors.New("invalid UDP length")
	errInvalidIHL       = errors.New("invalid IP IHL")
	errIPVersion        = errors.New("IP version not supported")

	errPortNoSpace     = errors.New("port limit reached")
	errPortNoneAvail   = errors.New("port unavailable")
	errPortNonexistent = errors.New("port nonexistent")
)

func (ps *PortStack) Addr() netip.Addr { return netip.AddrFrom4(ps.ip) }
func (ps *PortStack) SetAddr(addr netip.Addr) {
	if !addr.Is4() {
		panic("SetAddr only supports IPv4, or argument is not an IP address")
	}
	ps.ip = addr.As4()
}

func (ps *PortStack) MAC() net.HardwareAddr { return slices.Clone(ps.mac[:]) }
func (ps *PortStack) MACAs6() [6]byte       { return ps.mac }

// RecvEth validates an ethernet+ipv4 frame in payload. If it is OK then it
// defers response handling of the packets during a call to [Stack.HandleEth].
//
// If [Stack.HandleEth] is not called often enough prevent packet queue from
// filling up on a socket RecvEth will start to return [ErrDroppedPacket].
func (ps *PortStack) RecvEth(ethernetFrame []byte) (err error) {
	var ehdr eth.EthernetHeader
	var ihdr eth.IPv4Header
	defer func() {
		if err != nil {
			ps.error("Stack.RecvEth", slog.String("err", err.Error()), slog.Any("IP", ihdr))
		} else {
			ps.lastRxSuccess = ps.lastRx
			if ps.glob != nil {
				ps.glob(ethernetFrame)
			}
		}
	}()
	payload := ethernetFrame
	if len(payload) < eth.SizeEthernetHeader+eth.SizeIPv4Header {
		return errPacketSmol
	}
	ps.debug("Stack.RecvEth:start", slog.Int("plen", len(payload)))
	ps.lastRx = ps.now()

	// Ethernet parsing block
	ehdr = eth.DecodeEthernetHeader(payload)
	etype := ehdr.AssertType()
	if !eth.IsBroadcastHW(ehdr.Destination[:]) && !bytes.Equal(ehdr.Destination[:], ps.mac[:]) {
		return nil // Ignore packet, is not for us.
	} else if etype != eth.EtherTypeIPv4 && etype != eth.EtherTypeARP {
		return nil // Ignore Non-IPv4 packets.
	}

	if etype == eth.EtherTypeARP {
		ahdr := eth.DecodeARPv4Header(payload[eth.SizeEthernetHeader:])
		if ahdr.HardwareLength != 6 || ahdr.ProtoLength != 4 || ahdr.HardwareType != 1 || ahdr.AssertEtherType() != eth.EtherTypeIPv4 {
			return errors.New("unsupported ARP") // Ignore ARP unsupported requests.
		}
		switch ahdr.Operation {
		case 1: // ARP request.
			if ps.pendingReplyToARP() || ahdr.ProtoTarget != ps.ip {
				return nil // ARP reply pending or not for us.
			}
			// We need to respond to this ARP request.
			ahdr.HardwareTarget = ps.MACAs6()
			ahdr.Operation = 2 // Set as reply. This also flags the packet as pending.
			ps.pendingARPresponse = ahdr

		case 2: // ARP reply.
			if ps.ARPresult.Operation != arpOpWait || ahdr.ProtoSender != ps.ip ||
				ahdr.ProtoTarget != ps.ARPresult.ProtoTarget {
				return nil // Result already received | not for us | does not correspond to last request.
			}
			ps.ARPresult = ahdr
		default:
			return errors.New("unsupported ARP operation")
		}
		return nil
	}

	// IP parsing block.
	var ipOffset uint8
	ihdr, ipOffset = eth.DecodeIPv4Header(payload[eth.SizeEthernetHeader:])
	offset := eth.SizeEthernetHeader + ipOffset // Can be at most 14+60=74, so no overflow risk.
	end := eth.SizeEthernetHeader + ihdr.TotalLength
	switch {
	case ihdr.Version() != 4:
		return errIPVersion
	case ipOffset < eth.SizeIPv4Header:
		return errInvalidIHL

	case ps.ip != ihdr.Destination:
		return nil // Not for us.
	case uint16(offset) > end || int(offset) > len(payload) || int(end) > len(payload):
		return errors.New("bad IP TotalLength/IHL")
	case end > _MTU:
		return errPacketExceedsMTU
	}
	ipOptions := payload[eth.SizeEthernetHeader+eth.SizeIPv4Header : offset] // TODO add IPv4 options.
	payload = payload[offset:end]
	switch ihdr.Protocol {

	case 17:
		// UDP (User Datagram Protocol).
		if len(ps.portsUDP) == 0 {
			return nil // No sockets.
		} else if len(payload) < eth.SizeUDPHeader {
			return errTooShortTCPOrUDP
		}
		uhdr := eth.DecodeUDPHeader(payload)
		switch {
		case uhdr.DestinationPort == 0 || uhdr.SourcePort == 0:
			return errZeroPort
		case uhdr.Length < 8:
			return errBadUDPLength
		}

		payload = payload[eth.SizeUDPHeader:]
		gotsum := uhdr.CalculateChecksumIPv4(&ihdr, payload)
		if gotsum != uhdr.Checksum {
			return errChecksumTCPorUDP
		}

		port := findPort(ps.portsUDP, uhdr.DestinationPort)
		if port == nil {
			break // No socket listening on this port.
		} else if port.NeedsHandling() {
			ps.error("UDP packet dropped")
			ps.droppedPackets++
			return ErrDroppedPacket // Our socket needs handling before admitting more packets.
		}
		// The packet is meant for us. We handle it.
		ps.info("UDP packet stored", slog.Int("plen", len(payload)))
		// Flag packets as needing processing.
		ps.pendingUDPv4++
		port.LastRx = ps.lastRx // set as unhandled here.

		port.packets[0].Rx = ps.lastRx
		port.packets[0].Eth = ehdr
		port.packets[0].IP = ihdr
		port.packets[0].UDP = uhdr

		copy(port.packets[0].payload[:], payload)

	case 6:
		ps.info("TCP packet received", slog.Int("plen", len(payload)))
		// TCP (Transport Control Protocol).
		switch {
		case len(ps.portsTCP) == 0:
			return nil
		case len(payload) < eth.SizeTCPHeader:
			return errTooShortTCPOrUDP
		}

		thdr, offset := eth.DecodeTCPHeader(payload)
		switch {
		case thdr.DestinationPort == 0 || thdr.SourcePort == 0:
			return errZeroPort
		case offset < eth.SizeTCPHeader || int(offset) > len(payload):
			return errBadTCPOffset
		}
		tcpOptions := payload[eth.SizeTCPHeader:offset]
		payload = payload[offset:]
		gotsum := thdr.CalculateChecksumIPv4(&ihdr, tcpOptions, payload)
		if gotsum != thdr.Checksum {
			// return errChecksumTCPorUDP
			println("bad checksum")
		}
		port := findPort(ps.portsTCP, thdr.DestinationPort)
		if port == nil {
			break // No socket listening on this port.
		} else if port.NeedsHandling() {
			ps.error("TCP packet dropped")
			ps.droppedPackets++
			return ErrDroppedPacket // Our socket needs handling before admitting more packets.
		}
		ps.info("TCP packet stored", slog.Int("plen", len(payload)))
		// Flag packets as needing processing.
		ps.pendingTCPv4++
		port.LastRx = ps.lastRx // set as unhandled here.

		port.packets[0].Rx = ps.lastRx
		port.packets[0].Eth = ehdr
		port.packets[0].IP = ihdr
		port.packets[0].TCP = thdr
		n := copy(port.packets[0].data[:], ipOptions)
		n += copy(port.packets[0].data[n:], tcpOptions)
		copy(port.packets[0].data[n:], payload)
	}
	return nil
}

// HandleEth searches for a socket with a pending packet and writes the response
// into the dst argument. The length written to dst is returned.
// [ErrFlagPending] can be returned by value by a handler to indicate the packet was
// not processed and that a future call to HandleEth is required to complete.
//
// If a handler returns any other error the port is closed.
func (ps *PortStack) HandleEth(dst []byte) (n int, err error) {
	defer func() {
		if n > 0 && err == nil {
			ps.lastTx = ps.now()
		}
	}()
	switch {
	case len(dst) < _MTU:
		return 0, io.ErrShortBuffer

	case ps.pendingRequestARP():
		// We have a pending request from user to perform ARP.
		ehdr := eth.EthernetHeader{
			Destination:     broadcastMAC,
			Source:          ps.MACAs6(),
			SizeOrEtherType: uint16(eth.EtherTypeARP),
		}
		ehdr.Put(dst)
		ps.ARPresult.Put(dst[eth.SizeEthernetHeader:])
		ps.ARPresult.Operation = arpOpWait // Clear pending ARP to not loop.
		return eth.SizeEthernetHeader + eth.SizeARPv4Header, nil

	case ps.pendingReplyToARP():
		// We need to respond to an ARP request that queries our address.
		ehdr := eth.EthernetHeader{
			Destination:     ps.pendingARPresponse.HardwareSender,
			Source:          ps.MACAs6(),
			SizeOrEtherType: uint16(eth.EtherTypeARP),
		}
		ehdr.Put(dst)
		ps.pendingARPresponse.Put(dst[eth.SizeEthernetHeader:])
		ps.pendingARPresponse.Operation = 0 // Clear pending ARP.
		return eth.SizeEthernetHeader + eth.SizeARPv4Header, nil

	case ps.pendingUDPv4 == 0 && ps.pendingTCPv4 == 0:
		return 0, nil // No ARP or packets to handle.
	}

	ps.info("HandleEth", slog.Int("dstlen", len(dst)))

	type Socket interface {
		Close()
		IsPendingHandling() bool
		HandleEth(dst []byte) (int, error)
	}

	handleSocket := func(dst []byte, sock Socket) (int, bool, error) {
		if !sock.IsPendingHandling() {
			return 0, false, nil // Nothing to handle, just skip.
		}
		// Socket has an unhandled packet.
		n, err := sock.HandleEth(dst)
		if err == ErrFlagPending {
			// Special case: Socket may have written data but needs future handling, flagged with the ErrFlagPending error.
			return n, true, nil
		}
		if err != nil {
			sock.Close()
			n = 0
		}
		return n, false, err
	}

	if ps.pendingUDPv4 > 0 {
		for i := range ps.portsUDP {
			n, pending, err := handleSocket(dst, &ps.portsUDP[i])
			if !pending {
				ps.pendingUDPv4--
			}
			if err != nil {
				return 0, err
			} else if n > 0 {
				ps.processedPackets++
				return n, nil
			}
		}
	}

	if ps.pendingTCPv4 > 0 {
		for i := range ps.portsTCP {
			n, pending, err := handleSocket(dst, &ps.portsTCP[i])
			if !pending {
				ps.pendingTCPv4--
			}
			if err != nil {
				return 0, err
			} else if n > 0 {
				ps.processedPackets++
				return n, nil
			}
		}
	}

	return 0, nil // Nothing handled.
}

var broadcastMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (ps *PortStack) BeginResolveARPv4(target [4]byte) {
	ps.ARPresult = eth.ARPv4Header{
		Operation:      1, // Request.
		HardwareType:   1, // Ethernet.
		ProtoType:      uint16(eth.EtherTypeIPv4),
		HardwareLength: 6,
		ProtoLength:    4,
		HardwareSender: ps.MACAs6(),
		ProtoSender:    ps.ip,
		HardwareTarget: [6]byte{}, // Zeroes, is filled by target.
		ProtoTarget:    target,
	}
}

// ARPv4Result returns the result of the last ARPv4 request.
func (ps *PortStack) ARPv4Result() (eth.ARPv4Header, bool) {
	return ps.ARPresult, ps.ARPresult.Operation == 2
}

func (ps *PortStack) pendingReplyToARP() bool {
	return ps.pendingARPresponse.Operation == 2 // 2 means reply.
}

func (ps *PortStack) pendingRequestARP() bool {
	return ps.ARPresult.Operation == 1 // User asked for a ARP request.
}

// IsPendingHandling checks if a call to HandleEth could possibly result in a packet being generated by the PortStack.
func (ps *PortStack) IsPendingHandling() bool {
	return ps.pendingUDPv4 > 0 || ps.pendingTCPv4 > 0 || ps.pendingRequestARP() || ps.pendingReplyToARP()
}

// OpenUDP opens a UDP port and sets the handler.
// OpenUDP returns an error if the port is already open
// or if there is no socket available it returns an error.
//
// See [PortStack] for information on handler argument.
func (ps *PortStack) OpenUDP(portNum uint16, handler func([]byte, *UDPPacket) (int, error)) error {
	switch {
	case portNum == 0:
		return errZeroPort
	case handler == nil:
		return errNilHandler
	}

	port, err := findAvailPort(ps.portsUDP, portNum)
	if err != nil {
		return err
	}
	port.Open(portNum, handler)
	return nil
}

// FlagPendingUDP flags a given UDP port as having a pending packet.
// This is useful to force a response even if no packet has been received.
//
// See [PortStack] for more information on how packets are processed.
func (ps *PortStack) FlagPendingUDP(portNum uint16) error {
	if portNum == 0 {
		return errZeroPort
	}
	port := findPort(ps.portsUDP, portNum)
	if port == nil {
		return errPortNonexistent
	}
	if port.forceResponse() {
		ps.pendingUDPv4++
	}
	return nil
}

// CloseUDP closes a UDP port. See [PortStack].
func (ps *PortStack) CloseUDP(portNum uint16) error {
	if portNum == 0 {
		return errZeroPort
	}
	port := findPort(ps.portsUDP, portNum)
	if port == nil {
		return errPortNonexistent
	}
	ps.pendingUDPv4 -= uint32(port.pending())
	port.Close()
	return nil
}

// OpenTCP opens a TCP port and sets the handler.
// OpenTCP returns an error if the port is already open
// or if there is no socket available it returns an error.
//
// See [PortStack] for information on handler argument.
func (ps *PortStack) OpenTCP(portNum uint16, handler tcphandler) error {
	switch {
	case portNum == 0:
		return errZeroPort
	case handler == nil:
		return errNilHandler
	}
	p, err := findAvailPort(ps.portsTCP, portNum)
	if err != nil {
		return err
	}
	p.Open(portNum, handler)
	return nil
}

// FlagPendingTCP flags a given TCP port as having a pending packet.
// This is useful to force a response even if no packet has been received.
//
// See [PortStack] for more information on how packets are processed.
func (ps *PortStack) FlagPendingTCP(portNum uint16) error {
	if portNum == 0 {
		return errZeroPort
	}
	port := findPort(ps.portsTCP, portNum)
	if port == nil {
		return errPortNonexistent
	}
	if port.forceResponse() {
		ps.pendingTCPv4++
	}
	return nil
}

// CloseTCP closes the TCP port, effectively aborting the connection. See [PortStack].
func (ps *PortStack) CloseTCP(portNum uint16) error {
	if portNum == 0 {
		return errZeroPort
	}
	port := findPort(ps.portsTCP, portNum)
	if port == nil {
		return errPortNonexistent
	}
	ps.pendingTCPv4 -= port.pending()
	port.Close()
	return nil
}

func (ps *PortStack) now() time.Time {
	return time.Now()
}

func (ps *PortStack) info(msg string, attrs ...slog.Attr) {
	ps.logAttrsPrint(slog.LevelInfo, msg, attrs...)
}

func (ps *PortStack) error(msg string, attrs ...slog.Attr) {
	ps.logAttrsPrint(slog.LevelError, msg, attrs...)
}

func (ps *PortStack) debug(msg string, attrs ...slog.Attr) {
	ps.logAttrsPrint(slog.LevelDebug, msg, attrs...)
}

func (ps *PortStack) logAttrsPrint(level slog.Level, msg string, attrs ...slog.Attr) {
	if ps.logger != nil {
		ps.logger.LogAttrs(context.Background(), level, msg, attrs...)
	}
}

// logAttrsPrint is a hand-rolled slog.Handler implementation for use in memory contrained systems.
func logAttrsPrint(level slog.Level, msg string, attrs ...slog.Attr) {
	var levelStr string = level.String()

	print(levelStr)
	print(" ")
	print(msg)

	for _, a := range attrs {
		print(" ")
		print(a.Key)
		print("=")
		if a.Value.Kind() == slog.KindAny {
			fmt.Printf("%+v", a.Value.Any())
		} else {
			print(a.Value.String())
		}
	}
	println()
}

var _ porter = udpPort{}
var _ porter = tcpPort{}

type porter interface {
	Port() uint16
}

func findPort[T porter](list []T, port uint16) *T {
	for i := range list {
		if list[i].Port() == port {
			return &list[i]
		}
	}
	return nil
}

func findAvailPort[T porter](list []T, port uint16) (*T, error) {
	availableIdx := -1
	for i := range list {
		got := list[i].Port()
		if got == port {
			availableIdx = -2
			break
		} else if got == 0 { // Port==0 means port is unused.
			availableIdx = i
			break
		}
	}
	switch availableIdx {
	case -1:
		return nil, errPortNoSpace
	case -2:
		return nil, errPortNoneAvail
	}
	return &list[availableIdx], nil
}

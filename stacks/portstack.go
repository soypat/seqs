package stacks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/eth/dhcp"
	"tinygo.org/x/drivers/netlink"
)

const (
	defaultMTU = 2048
	arpOpWait  = 0xffff
)

type ethernethandler = func(ehdr *eth.EthernetHeader, ethPayload []byte) error

type PortStackConfig struct {
	MaxOpenPortsUDP int
	MaxOpenPortsTCP int
	// GlobalHandler processes all incoming ethernet frames before they reach the port handlers.
	// If GlobalHandler returns an error the frame is discarded and PortStack.HandleEth returns the error.
	GlobalHandler ethernethandler
	Logger        *slog.Logger
	// MTU is the maximum transmission unit of the ethernet interface.
	MTU  uint16
	Link netlink.Netlinker
}

// NewPortStack creates a ready to use TCP/UDP Stack instance.
func NewPortStack(cfg PortStackConfig) *PortStack {
	s := &PortStack{}
	s.arpClient.stack = s
	// s.ip = cfg.IP.As4()
	s.portsUDP = make([]udpPort, cfg.MaxOpenPortsUDP)
	s.portsTCP = make([]tcpPort, cfg.MaxOpenPortsTCP)
	s.logger = cfg.Logger
	if cfg.MTU > defaultMTU {
		panic("please use a smaller MTU. max=" + strconv.Itoa(defaultMTU))
	}
	s.mtu = cfg.MTU
	s.link = cfg.Link
	s.link.NetNotify(s.Notify)
	s.link.RecvEthHandle(s.RecvEth)
	return s
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
//     is immediately closed.
//
//   - [io.EOF] and ErrFlagPending: When returned by handler data written is not discarded.
//     This means that the handler can write data and close port in same operation returning non-zero `n` and EOF.
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
	link          netlink.Netlinker
	lastRx        time.Time
	lastRxSuccess time.Time
	lastTx        time.Time
	glob          ethernethandler
	logger        *slog.Logger
	portsUDP      []udpPort
	portsTCP      []tcpPort

	pendingUDPv4     uint32
	pendingTCPv4     uint32
	processedPackets uint32
	// droppedPackets counts amount of packets corresponding to TCP/UDP ports
	// that have been dropped due to the port requiring handling before admitting more packets.
	droppedPackets uint32
	// ARP state. See arp.go for detailed information on the ARP state machine.
	arpClient arpClient
	// Auxiliary struct to avoid allocations passed to global handler.
	auxEth eth.EthernetHeader
	mac    [6]byte
	ip     [4]byte
	mtu    uint16
	auxUDP UDPPacket
	auxTCP TCPPacket
}

// Common errors.
var (
	ErrDroppedPacket    = errors.New("dropped packet")
	errPacketExceedsMTU = errors.New("packet exceeds MTU")
	// errNotIPv4          = errors.New("require IPv4")
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

func (ps *PortStack) Addr() (netip.Addr, error) { return netip.AddrFrom4(ps.ip), nil }
func (ps *PortStack) SetAddr(addr netip.Addr) {
	if !addr.Is4() {
		panic("SetAddr only supports IPv4, or argument not initialized")
	}
	ps.ip = addr.As4()
}

func (ps *PortStack) MTU() uint16                 { return ps.mtu }
func (ps *PortStack) MAC() net.HardwareAddr       { return slices.Clone(ps.mac[:]) }
func (ps *PortStack) MACAs6() [6]byte             { return ps.mac }
func (ps *PortStack) SetMAC(mac net.HardwareAddr) { copy(ps.mac[:], mac) }

// RecvEth validates an ethernet+ipv4 frame in payload. If it is OK then it
// defers response handling of the packets during a call to [Stack.HandleEth].
//
// If [Stack.HandleEth] is not called often enough prevent packet queue from
// filling up on a socket RecvEth will start to return [ErrDroppedPacket].
func (ps *PortStack) RecvEth(ethernetFrame []byte) (err error) {
	var ihdr eth.IPv4Header
	payload := ethernetFrame
	if len(payload) < eth.SizeEthernetHeader+eth.SizeIPv4Header {
		return errPacketSmol
	} else if len(payload) > int(ps.mtu) {
		println("recv", payload, ps.mtu)
		return errPacketExceedsMTU
	}
	ps.trace("Stack.RecvEth:start", slog.Int("plen", len(payload)))
	ps.lastRx = ps.now()
	// Ethernet parsing block
	ps.auxEth = eth.DecodeEthernetHeader(payload)
	ehdr := &ps.auxEth
	if ps.glob != nil {
		err = ps.glob(&ps.auxEth, payload[eth.SizeEthernetHeader:])
		if err != nil {
			return err
		}
	}
	etype := ehdr.AssertType()
	if !eth.IsBroadcastHW(ehdr.Destination[:]) && !bytes.Equal(ehdr.Destination[:], ps.mac[:]) {
		return nil // Ignore packet, is not for us.
	} else if etype != eth.EtherTypeIPv4 && etype != eth.EtherTypeARP {
		return nil // Ignore Non-IPv4 packets.
	}

	if etype == eth.EtherTypeARP {
		if len(payload) < eth.SizeEthernetHeader+eth.SizeARPv4Header {
			return errPacketSmol
		}
		ahdr := eth.DecodeARPv4Header(payload[eth.SizeEthernetHeader:])
		return ps.arpClient.recv(&ahdr)
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

	case ps.ip != ihdr.Destination && ps.ip != [4]byte{}:
		return nil // Not for us.
	case uint16(offset) > end || int(offset) > len(payload) || int(end) > len(payload):
		return errors.New("bad IP TotalLength/IHL")
	case end > ps.mtu:
		return errPacketExceedsMTU
	}
	ipOptions := payload[eth.SizeEthernetHeader+eth.SizeIPv4Header : offset] // TODO add IPv4 options.
	payload = payload[offset:end]
	switch ihdr.Protocol {
	default:
		err = errors.New("unknown IP protocol")
	case 17:
		// UDP (User Datagram Protocol).
		if len(ps.portsUDP) == 0 {
			break // No sockets.
		} else if len(payload) < eth.SizeUDPHeader {
			err = errTooShortTCPOrUDP
			break
		}
		uhdr := eth.DecodeUDPHeader(payload)
		if uhdr.DestinationPort == 0 || uhdr.SourcePort == 0 {
			err = errZeroPort
			break
		} else if uhdr.Length < 8 {
			err = errBadUDPLength
			break
		}

		payload = payload[eth.SizeUDPHeader:]
		gotsum := uhdr.CalculateChecksumIPv4(&ihdr, payload)
		if gotsum != uhdr.Checksum {
			err = errChecksumTCPorUDP
			break
		}

		port := findPort(ps.portsUDP, uhdr.DestinationPort)
		if port == nil {
			break // No socket listening on this port.
		}

		pkt := &ps.auxUDP
		if pkt == nil {
			ps.error("UDP packet dropped")
			ps.droppedPackets++
			err = ErrDroppedPacket // Our socket needs handling before admitting more packets.
			break
		}
		// The packet is meant for us. We handle it.
		ps.debug("UDP:recv", slog.Int("plen", len(payload)))
		// Flag packets as needing processing.
		ps.pendingUDPv4++

		pkt.Rx = ps.lastRx
		pkt.Eth = *ehdr
		pkt.IP = ihdr // TODO(soypat): Don't ignore IP options.
		pkt.UDP = uhdr
		copy(pkt.payload[:], payload)
		port.ihandler.recv(pkt)
		if err == io.EOF {
			// Special case; EOF is flag to close port
			err = nil
			port.Close()
			ps.debug("UDP:closed", slog.Int("port", int(port.Port())))
		} else if err == ErrFlagPending {
			err = nil // TODO(soypat).
		}

	case 6:
		// TCP (Transport Control Protocol).
		if len(ps.portsTCP) == 0 {
			break // No sockets.
		} else if len(payload) < eth.SizeTCPHeader {
			err = errTooShortTCPOrUDP
			break
		}

		thdr, offset := eth.DecodeTCPHeader(payload)
		if thdr.DestinationPort == 0 || thdr.SourcePort == 0 {
			err = errZeroPort
			break
		} else if offset < eth.SizeTCPHeader || int(offset) > len(payload) {
			err = errBadTCPOffset
			break
		}

		tcpOptions := payload[eth.SizeTCPHeader:offset]
		payload = payload[offset:]
		gotsum := thdr.CalculateChecksumIPv4(&ihdr, tcpOptions, payload)

		if gotsum != thdr.Checksum {
			err = errChecksumTCPorUDP
			break
		}
		port := findPort(ps.portsTCP, thdr.DestinationPort)
		if port == nil {
			ps.debug("tcp:noSocket", slog.Int("port", int(thdr.DestinationPort)), slog.Int("avail", len(ps.portsTCP)))
			break // No socket listening on this port.
		}

		pkt := &ps.auxTCP
		if pkt == nil {
			ps.error("TCP packet dropped")
			ps.droppedPackets++
			err = ErrDroppedPacket // Our socket needs handling before admitting more packets.
			break
		}
		ps.debug("TCP:recv",
			slog.Int("opt", len(tcpOptions)),
			slog.Int("ipopt", len(ipOptions)),
			slog.Int("payload", len(payload)),
		)
		ps.pendingTCPv4++
		pkt.Rx = ps.lastRx
		pkt.Eth = *ehdr
		pkt.IP = ihdr
		pkt.TCP = thdr
		n := copy(pkt.data[:], ipOptions)
		n += copy(pkt.data[n:], tcpOptions)
		copy(pkt.data[n:], payload)
		err = port.handler.recv(pkt)
		if err == io.EOF {
			// Special case; EOF is flag to close port
			err = nil
			port.Close()
			ps.debug("TCP:closed", slog.Int("port", int(port.Port())))
		} else if err == ErrFlagPending {
			err = nil // TODO(soypat).
		}
	}
	if err != nil {
		ps.error("Stack.RecvEth", slog.String("err", err.Error()))
	}
	return err
}

func (ps *PortStack) HandleEth(dst []byte) (n int, err error) {
	ps.trace("HandleEth:start", slog.Int("dstlen", len(dst)))
	n, err = ps.handleEth(dst)
	if n > 0 && err == nil {
		ps.trace("HandleEth:send", slog.Int("plen", n))
		ps.lastTx = ps.now()
		ps.processedPackets++
	} else if err != nil {
		ps.error("HandleEth", slog.String("err", err.Error()))
	}
	return n, err
}

// HandleEth searches for a socket with a pending packet and writes the response
// into the dst argument. The length written to dst is returned.
// [ErrFlagPending] can be returned by value by a handler to indicate the packet was
// not processed and that a future call to HandleEth is required to complete.
//
// If a handler returns any other error the port is closed.
func (ps *PortStack) handleEth(dst []byte) (n int, err error) {
	switch {
	case len(dst) < int(ps.mtu):
		return 0, io.ErrShortBuffer

	case !ps.IsPendingHandling():
		return 0, nil // No remaining packets to handle.
	}
	n = ps.arpClient.handle(dst)
	if n != 0 {
		return n, nil
	}

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
			if err == io.EOF {
				// Special case: If error is EOF we don't return it to caller but we do write the packet if any.
				err = nil
			} else {
				n = 0 // Clear n on unknown error and return error up the call stack.
			}
		}
		return n, sock.IsPendingHandling(), err
	}

	socketPending := false
	if ps.pendingUDPv4 > 0 {
		for i := range ps.portsUDP {
			n, pending, err := handleSocket(dst, &ps.portsUDP[i])
			if pending {
				socketPending = true
			}
			if err != nil {
				return 0, err
			} else if n > 0 {
				ps.debug("UDP:send", slog.Int("plen", n))
				return n, nil
			}
		}
		if !socketPending {
			ps.pendingUDPv4 = 0 // No more pending UDP sockets.
		}
	}

	socketPending = false
	if ps.pendingTCPv4 > 0 {
		for i := range ps.portsTCP {
			n, pending, err := handleSocket(dst, &ps.portsTCP[i])
			if pending {
				pending = true
			}
			if err != nil {
				return 0, err
			} else if n > 0 {
				ps.debug("TCP:send", slog.Int("plen", n))
				return n, nil
			}
		}
		if !socketPending {
			ps.pendingTCPv4 = 0 // No more pending TCP sockets.
		}
	}

	return 0, nil // Nothing handled.
}

// IsPendingHandling checks if a call to HandleEth could possibly result in a packet being generated by the PortStack.
func (ps *PortStack) IsPendingHandling() bool {
	return ps.pendingUDPv4 > 0 || ps.pendingTCPv4 > 0 || ps.arpClient.isPending()
}

// OpenUDP opens a UDP port and sets the handler.
// OpenUDP returns an error if the port is already open
// or if there is no socket available it returns an error.
//
// See [PortStack] for information on handler argument.
func (ps *PortStack) OpenUDP(portNum uint16, handler iudphandler) error {
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
	ps.pendingUDPv4++
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
	port.Close()
	return nil
}

// OpenTCP opens a TCP port and sets the handler.
// OpenTCP returns an error if the port is already open
// or if there is no socket available it returns an error.
//
// See [PortStack] for information on handler argument.
func (ps *PortStack) OpenTCP(portNum uint16, handler itcphandler) error {
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
	ps.pendingTCPv4++
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
	port.Close()
	return nil
}

func (ps *PortStack) Bind(sockfd int, ip netip.AddrPort) error {
	return errors.New("Bind not implemented")
}

func (ps *PortStack) Accept(sockfd int, ip netip.AddrPort) (int, error) {
	return -1, errors.New("Accept not implemented")
}

func (ps *PortStack) Close(sockfd int) error {
	return errors.New("Close not implemented")
}

func (ps *PortStack) Connect(sockfd int, host string, ip netip.AddrPort) error {
	return errors.New("Connect not implemented")
}

func (ps *PortStack) GetHostByName(name string) (netip.Addr, error) {
	return netip.Addr{}, errors.New("GetHostByName not implemented")
}

func (ps *PortStack) Listen(sockfd int, backlog int) error {
	return errors.New("Listen not implemented")
}

func (ps *PortStack) Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	return 0, errors.New("Recv not implemented")
}

func (ps *PortStack) Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	return 0, errors.New("Send not implemented")
}

func (ps *PortStack) SetSockOpt(sockfd int, level int, opt int, value interface{}) error {
	return errors.New("SetSockOpt not implemented")
}

func (ps *PortStack) Socket(domain int, stype int, protocol int) (int, error) {
	return -1, errors.New("Socket not implemented")
}

func (ps *PortStack) linkUp() {
	println("Link is UP")

	// Make a copy of the device MAC as [6]byte
	mac, _ := ps.link.GetHardwareAddr()
	ps.SetMAC(mac)

	// Begin asynchronous packet handling.
	go ps.NICLoop()

	// Perform DHCP request.
	dhcpClient := NewDHCPClient(ps, dhcp.DefaultClientPort)
	err := dhcpClient.BeginRequest(DHCPRequestConfig{
		RequestedAddr: netip.AddrFrom4([4]byte{192, 168, 1, 69}),
		Xid:           0x12345678,
	})
	if err != nil {
		panic("dhcp failed: " + err.Error())
	}
	for !dhcpClient.Done() {
		println("dhcp ongoing...")
		time.Sleep(time.Second / 2)
	}
	ip := dhcpClient.Offer()
	println("DHCP complete IP:", ip.String())
	ps.SetAddr(ip) // It's important to set the IP address after DHCP completes.

	// Interface is UP
	println("Interface is UP")
}

func (ps *PortStack) linkDown() {
	println("Link is DOWN")
	// TODO kill NICLoop()
	// Interface is DOWN
	println("Interface is DOWN")
}

func (ps *PortStack) Notify(event netlink.Event) {
	switch event {
	case netlink.EventNetUp:
		ps.linkUp()
	case netlink.EventNetDown:
		ps.linkDown()
	}
}

// Test GC stats printing.
var (
	memstats   runtime.MemStats
	lastAllocs uint64
	lastLog    time.Time
)

const enableGCPrint = true
const minLogPeriod = 8 * time.Second

// printGCStatsIfChanged prints GC stats if they have changed since the last call and
// at least minLogPeriod has passed.
func printGCStatsIfChanged(log *slog.Logger) {
	if !enableGCPrint {
		return
	}
	// Split logging into two calls since slog inlines at most 5 arguments per call.
	// This way we avoid heap allocations for the log message to avoid interfering with GC.
	runtime.ReadMemStats(&memstats)
	now := time.Now()
	if memstats.TotalAlloc == lastAllocs || now.Sub(lastLog) < minLogPeriod {
		return // don't print if no change in allocations.
	}
	println("GC stats ", now.Unix())
	print(" TotalAlloc= ", memstats.TotalAlloc)
	print(" Frees=", memstats.Frees)
	print(" Mallocs=", memstats.Mallocs)
	print(" GCSys=", memstats.GCSys)
	println(" Sys=", memstats.Sys)
	print("HeapIdle=", memstats.HeapIdle)
	print(" HeapInuse=", memstats.HeapInuse)
	print(" HeapReleased=", memstats.HeapReleased)
	println(" HeapSys=", memstats.HeapSys)
	// log.LogAttrs(context.Background(), slog.LevelInfo, "MemStats",
	// 	slog.Uint64("TotalAlloc", memstats.TotalAlloc),
	// 	slog.Uint64("Frees", memstats.Frees),
	// 	slog.Uint64("Mallocs", memstats.Mallocs),
	// 	slog.Uint64("GCSys", memstats.GCSys),
	// 	slog.Uint64("Sys", memstats.Sys),
	// )
	// log.LogAttrs(context.Background(), slog.LevelInfo, "MemStats.Heap",
	// 	slog.Uint64("HeapIdle", memstats.HeapIdle),
	// 	slog.Uint64("HeapInuse", memstats.HeapInuse),
	// 	slog.Uint64("HeapReleased", memstats.HeapReleased),
	// 	slog.Uint64("HeapSys", memstats.HeapSys),
	// )
	// Above calls may allocate.
	runtime.ReadMemStats(&memstats)
	lastAllocs = memstats.TotalAlloc
	lastLog = now
}

func (ps *PortStack) NICLoop() {
	// Maximum number of packets to queue before sending them.
	const (
		queueSize                = 4
		maxRetriesBeforeDropping = 3
		// TODO want to use ps.MTU but that's not a constant, so...
		MTU                      = 2048
	)
	var queue [queueSize][MTU]byte
	var lenBuf [queueSize]int
	var retries [queueSize]int
	markSent := func(i int) {
		queue[i] = [MTU]byte{} // Not really necessary.
		lenBuf[i] = 0
		retries[i] = 0
	}
	for {
		printGCStatsIfChanged(ps.logger)
		stallRx := true
		// Poll for incoming packets.
		for i := 0; i < 1; i++ {
			gotPacket, err := ps.link.TryPoll()
			if err != nil {
				println("poll error:", err.Error())
			}
			if !gotPacket {
				break
			}
			stallRx = false
		}

		// Queue packets to be sent.
		for i := range queue {
			if retries[i] != 0 {
				continue // Packet currently queued for retransmission.
			}
			var err error
			buf := queue[i][:]
			lenBuf[i], err = ps.HandleEth(buf[:])
			if err != nil {
				println("stack error n(should be 0)=", lenBuf[i], "err=", err.Error())
				lenBuf[i] = 0
				continue
			}
			if lenBuf[i] == 0 {
				break
			}
		}
		stallTx := lenBuf == [queueSize]int{}
		if stallTx {
			if stallRx {
				// Avoid busy waiting when both Rx and Tx stall.
				time.Sleep(51 * time.Millisecond)
			}
			continue
		}

		// Send queued packets.
		for i := range queue {
			n := lenBuf[i]
			if n <= 0 {
				continue
			}
			err := ps.link.SendEth(queue[i][:n])
			if err != nil {
				// Queue packet for retransmission.
				retries[i]++
				if retries[i] > maxRetriesBeforeDropping {
					markSent(i)
					println("dropped outgoing packet:", err.Error())
				}
			} else {
				markSent(i)
			}
		}
	}
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

func (ps *PortStack) trace(msg string, attrs ...slog.Attr) {
	ps.logAttrsPrint(slog.LevelDebug-2, msg, attrs...)
}

func (ps *PortStack) isLogEnabled(lvl slog.Level) bool {
	return ps.logger != nil && ps.logger.Handler().Enabled(context.Background(), lvl)
}

func (ps *PortStack) logAttrsPrint(level slog.Level, msg string, attrs ...slog.Attr) {
	if ps.logger != nil {
		ps.logger.LogAttrs(context.Background(), level, msg, attrs...)
	}
}

func (ps *PortStack) SetLogger(log *slog.Logger) {
	ps.logger = log
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

func findPort[T porter](list []T, portNum uint16) *T {
	for i := range list {
		if list[i].Port() == portNum {
			return &list[i]
		}
	}
	return nil
}

func findAvailPort[T porter](list []T, portNum uint16) (*T, error) {
	availableIdx := -1
	for i := range list {
		got := list[i].Port()
		if got == portNum {
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

func bytesAttr(name string, b []byte) slog.Attr {
	return slog.Attr{
		Key:   name,
		Value: slog.StringValue(string(b)),
	}
}

package stacks

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/soypat/seqs/eth"
)

// ARP returns the ARP client for this stack. The type is not exported since
// it's implementation is experimental.
func (ps *PortStack) ARP() *arpClient {
	return &ps.arpClient
}

var (
	errARPUnsupported     = errors.New("unsupported ARP request")
	errNoARPInProgress    = errors.New("no ARP in progress")
	errARPResponsePending = errors.New("ARP response pending")
	errARPRequestPending  = errors.New("ARP request not yet sent")
)

/*
ARP PortStack state machine:

# ARP User Request (outgoing request)

PortStack.arpResult contains state:
1. Upon user request `BeginResolveARPv4`: PortStack.arpResult.Operation = 1 (request), which means request has not been sent out.
2. Upon `handleARP`: PortStack.arpResult.Operation = 0xffff (wait)
3. Upon corresponding ARP reply in `recvARP`: PortStack.arpResult.Operation = 2 (reply).

If `BeginResolveARPv4` is called at any point in resolution, the state is reset to 1.

# External ARP incoming request

PortStack.pendingARPresponse contains state:
1. Upon ARP request in `recvARP`, case 1: Store outgoing ARP response in PortStack.pendingARPresponse. PortStack.pendingARPresponse.Operation = 2 (reply)
2. Upon `handleARP`: Packet sent out. PortStack.pendingARPresponse.Operation = 0 (no pending response) Ready to receive.
*/
type arpClient struct {
	stack           *PortStack
	result          eth.ARPv4Header
	pendingResponse eth.ARPv4Header
}

func (c *arpClient) ResultAs6() (netip.Addr, [6]byte, error) {
	switch c.result.Operation {
	case 0:
		return netip.Addr{}, [6]byte{}, errNoARPInProgress
	case 1:
		return netip.Addr{}, [6]byte{}, errARPRequestPending
	case arpOpWait:
		return netip.Addr{}, [6]byte{}, errARPResponsePending
	}
	return netip.AddrFrom4(c.result.ProtoSender), c.result.HardwareSender, nil
}

func (c *arpClient) BeginResolve(addr netip.Addr) error {
	if !addr.Is4() {
		return errIPVersion
	}
	c.result = eth.ARPv4Header{
		Operation:      1, // Request.
		HardwareType:   1, // Ethernet.
		ProtoType:      uint16(eth.EtherTypeIPv4),
		HardwareLength: 6,
		ProtoLength:    4,
		HardwareSender: c.stack.HardwareAddr6(),
		ProtoSender:    c.stack.ip,
		HardwareTarget: [6]byte{}, // Zeroes, is filled by target.
		ProtoTarget:    addr.As4(),
	}
	return nil
}

func (c *arpClient) Abort() {
	c.result = eth.ARPv4Header{}
}

func (c *arpClient) IsDone() bool {
	return c.result.Operation == 2
}

func (c *arpClient) isPending() bool {
	return c.pendingReplyToARP() || c.pendingOutReqARPv4()
}

func (c *arpClient) pendingReplyToARP() bool {
	return c.pendingResponse.Operation == 2 // 2 means reply.
}

func (c *arpClient) pendingOutReqARPv4() bool {
	return c.result.Operation == 1 // User asked for a ARP request.
}

func (c *arpClient) handle(dst []byte) (n int) {
	pendingOutReq := c.pendingOutReqARPv4()
	switch {
	case pendingOutReq:
		// We have a pending request from user to perform ARP.
		ehdr := eth.EthernetHeader{
			Destination:     eth.BroadcastHW6(),
			Source:          c.stack.HardwareAddr6(),
			SizeOrEtherType: uint16(eth.EtherTypeARP),
		}
		ehdr.Put(dst)
		c.result.Put(dst[eth.SizeEthernetHeader:])
		c.result.Operation = arpOpWait // Clear pending ARP to not loop.
		n = eth.SizeEthernetHeader + eth.SizeARPv4Header

	case c.pendingReplyToARP():
		// We need to respond to an ARP request that queries our address.
		ehdr := eth.EthernetHeader{
			Destination:     c.pendingResponse.HardwareTarget,
			Source:          c.stack.HardwareAddr6(),
			SizeOrEtherType: uint16(eth.EtherTypeARP),
		}
		ehdr.Put(dst)
		c.pendingResponse.Put(dst[eth.SizeEthernetHeader:])
		c.pendingResponse.Operation = 0 // Clear pending ARP.
		n = eth.SizeEthernetHeader + eth.SizeARPv4Header

	default:
		// return 0 // Nothing to do, n=0.
	}
	if n > 0 && c.stack.isLogEnabled(slog.LevelDebug) {
		c.stack.debug("ARP:send", slog.Bool("isReply", !pendingOutReq))
	}
	return n
}

func (c *arpClient) recv(ahdr *eth.ARPv4Header) error {
	if ahdr.HardwareLength != 6 || ahdr.ProtoLength != 4 || ahdr.HardwareType != 1 || ahdr.AssertEtherType() != eth.EtherTypeIPv4 {
		return errARPUnsupported // Ignore ARP unsupported requests.
	}
	switch ahdr.Operation {
	case 1: // We received ARP request.
		if c.pendingReplyToARP() || ahdr.ProtoTarget != c.stack.ip {
			return nil // ARP reply pending or not for us.
		}
		// We need to respond to this ARP request by inverting Sender/Target fields.
		ahdr.HardwareTarget = ahdr.HardwareSender
		ahdr.ProtoTarget = ahdr.ProtoSender

		ahdr.HardwareSender = c.stack.HardwareAddr6()
		ahdr.ProtoSender = c.stack.ip
		ahdr.Operation = 2 // Set as reply. This also flags the packet as pending.
		c.pendingResponse = *ahdr

	case 2: // We received ARP reply.
		if c.result.Operation != arpOpWait || // Result already received
			ahdr.ProtoTarget != c.stack.ip || // Not meant for us.
			ahdr.ProtoSender != c.result.ProtoTarget { // does not correspond to last request.
			return nil
		}
		c.result = *ahdr
	default:
		return errARPUnsupported
	}
	if c.stack.isLogEnabled(slog.LevelDebug) {
		c.stack.debug("ARP:recv", slog.Int("op", int(ahdr.Operation)))
	}
	return nil
}

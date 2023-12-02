package stacks

import (
	"errors"
	"log/slog"

	"github.com/soypat/seqs/eth"
)

func (ps *PortStack) BeginResolveARPv4(target [4]byte) {
	ps.arpResult = eth.ARPv4Header{
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
	return ps.arpResult, ps.arpResult.Operation == 2
}

func (ps *PortStack) pendingReplyToARP() bool {
	return ps.pendingARPresponse.Operation == 2 // 2 means reply.
}

func (ps *PortStack) pendingResolveARPv4() bool {
	return ps.arpResult.Operation == 1 // User asked for a ARP request.
}

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

func (ps *PortStack) handleARP(dst []byte) (n int) {
	pendingResolve := ps.pendingResolveARPv4()
	switch {
	case pendingResolve:
		// We have a pending request from user to perform ARP.
		ehdr := eth.EthernetHeader{
			Destination:     eth.BroadcastHW6(),
			Source:          ps.MACAs6(),
			SizeOrEtherType: uint16(eth.EtherTypeARP),
		}
		ehdr.Put(dst)
		ps.arpResult.Put(dst[eth.SizeEthernetHeader:])
		ps.arpResult.Operation = arpOpWait // Clear pending ARP to not loop.
		n = eth.SizeEthernetHeader + eth.SizeARPv4Header

	case ps.pendingReplyToARP():
		// We need to respond to an ARP request that queries our address.
		ehdr := eth.EthernetHeader{
			Destination:     ps.pendingARPresponse.HardwareTarget,
			Source:          ps.MACAs6(),
			SizeOrEtherType: uint16(eth.EtherTypeARP),
		}
		ehdr.Put(dst)
		ps.pendingARPresponse.Put(dst[eth.SizeEthernetHeader:])
		ps.pendingARPresponse.Operation = 0 // Clear pending ARP.
		n = eth.SizeEthernetHeader + eth.SizeARPv4Header

	default:
		// return 0 // Nothing to do, n=0.
	}
	if n > 0 {
		ps.debug("ARP:send", slog.Bool("isReply", !pendingResolve))
	}
	return n
}

func (ps *PortStack) recvARP(ethPayload []byte) error {
	if len(ethPayload) < eth.SizeARPv4Header {
		return errors.New("short ARP payload")
	}
	ahdr := eth.DecodeARPv4Header(ethPayload)
	if ahdr.HardwareLength != 6 || ahdr.ProtoLength != 4 || ahdr.HardwareType != 1 || ahdr.AssertEtherType() != eth.EtherTypeIPv4 {
		return errors.New("unsupported ARP") // Ignore ARP unsupported requests.
	}
	switch ahdr.Operation {
	case 1: // We received ARP request.
		if ps.pendingReplyToARP() || ahdr.ProtoTarget != ps.ip {
			return nil // ARP reply pending or not for us.
		}
		// We need to respond to this ARP request by inverting Sender/Target fields.
		ahdr.HardwareTarget = ahdr.HardwareSender
		ahdr.ProtoTarget = ahdr.ProtoSender

		ahdr.HardwareSender = ps.MACAs6()
		ahdr.ProtoSender = ps.ip
		ahdr.Operation = 2 // Set as reply. This also flags the packet as pending.
		ps.pendingARPresponse = ahdr

	case 2: // We received ARP reply.
		if ps.arpResult.Operation != arpOpWait || // Result already received
			ahdr.ProtoTarget != ps.ip || // Not meant for us.
			ahdr.ProtoSender != ps.arpResult.ProtoTarget { // does not correspond to last request.
			return nil
		}
		ps.arpResult = ahdr
	default:
		return errors.New("unsupported ARP operation")
	}
	ps.debug("ARP:recv", slog.Int("op", int(ahdr.Operation)))
	return nil
}

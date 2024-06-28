package stacks

import (
	"github.com/soypat/seqs"
	"github.com/soypat/seqs/internal"
)

// SCB is an internal routine for testing which returns the control block,
// which is a simplified implementation of the TCB of RFC9293.
func (tcp *TCPConn) SCB() *seqs.ControlBlock { return &tcp.scb }

func (dhcpc *DHCPClient) PortStack() *PortStack { return dhcpc.stack }
func (dhcps *DHCPServer) PortStack() *PortStack { return dhcps.stack }

func (tcp *TCPConn) RingBuffers() (rx, tx *internal.Ring) {
	return &tcp.rx, &tcp.tx
}

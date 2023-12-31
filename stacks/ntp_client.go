package stacks

import "github.com/soypat/seqs/eth/ntp"

type NTPClient struct {
	stack      *PortStack
	timestamps [4]ntp.Timestamp
	org        ntp.Timestamp
	rec        ntp.Timestamp
	xmt        ntp.Timestamp
	lport      uint16
}

func NewNTPClient(stack *PortStack, lport uint16) *NTPClient {
	if stack == nil || lport == 0 {
		panic("nil stack or port")
	}
	return &NTPClient{
		stack: stack,
		lport: lport,
	}
}

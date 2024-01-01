package stacks

import (
	"net/netip"

	"github.com/soypat/seqs/eth/dns"
)

const (
	dnsClosed = iota
	dnsSendQuery
	dnsAwaitResponse
	dnsDone
	dnsAborted
)

type DNSClient struct {
	stack *PortStack
	pkt   UDPPacket
	rhw   [6]byte
	raddr netip.Addr
	lport uint16
	state uint8
	msg   dns.Message
}

func NewDNSClient(stack *PortStack, localPort uint16) *DNSClient {
	return &DNSClient{
		stack: stack,
		lport: localPort,
	}
}

type DNSResolveConfig struct {
	Questions []dns.Question
	DNSAddr   netip.Addr
	DNSHWAddr [6]byte
}

func (dnsc *DNSClient) StartResolve(cfg DNSResolveConfig) error {
	err := dnsc.stack.OpenUDP(dnsc.lport, dnsc)
	if err != nil {
		return err
	}
	err = dnsc.stack.FlagPendingUDP(dnsc.lport)
	if err != nil {
		return err
	}

	msg := &dnsc.msg
	msg.Reset()
	dnsc.raddr = cfg.DNSAddr
	nd := len(cfg.Questions)
	msg.LimitResourceDecoding(uint16(nd), uint16(nd), 0, 0)
	msg.AddQuestions(cfg.Questions)
	dnsc.state = dnsSendQuery
	return nil
}

func (dnsc *DNSClient) send(dst []byte) (n int, err error) {
	return 0, nil
}

func (dnsc *DNSClient) recv(pkt *UDPPacket) error {
	dnsc.stack.info("dns recv!")
	return nil
}

func (dnsc *DNSClient) isPendingHandling() bool {
	return dnsc.state == dnsSendQuery || dnsc.state == dnsAborted
}

func (dnsc *DNSClient) Abort() {
	dnsc.state = dnsAborted
}

func (dnsc *DNSClient) abort() {
	*dnsc = DNSClient{
		stack: dnsc.stack,
		lport: dnsc.lport,
		msg:   dnsc.msg,
	}
	dnsc.msg.Reset()
}

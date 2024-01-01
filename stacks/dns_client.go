package stacks

import (
	"io"
	"net/netip"

	"github.com/soypat/seqs/eth"
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
	txid  uint16
	raddr netip.Addr
	lport uint16
	state uint8
	msg   dns.Message

	enableRecursion bool
}

func NewDNSClient(stack *PortStack, localPort uint16) *DNSClient {
	return &DNSClient{
		stack: stack,
		lport: localPort,
	}
}

type DNSResolveConfig struct {
	Questions       []dns.Question
	DNSAddr         netip.Addr
	DNSHWAddr       [6]byte
	EnableRecursion bool
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
	dnsc.txid += 37
	dnsc.enableRecursion = cfg.EnableRecursion
	return nil
}

func (dnsc *DNSClient) send(dst []byte) (n int, err error) {
	if dnsc.state == dnsAborted {
		return 0, io.EOF
	} else if dnsc.state != dnsSendQuery {
		return 0, nil
	}
	const payloadOffset = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
	msg := &dnsc.msg
	msgLen := msg.Len()
	payload := dst[payloadOffset:]
	if int(msgLen) > len(payload) {
		return 0, io.ErrShortBuffer
	}

	dnsc.txid = prand16(msgLen * dnsc.txid)
	msg.Header = dns.Header{
		Flags:         dns.NewClientHeaderFlags(dns.OpCodeQuery, dnsc.enableRecursion),
		TransactionID: dnsc.txid,
	}

	const ipv4ToS = 0
	setUDP(&dnsc.pkt, dnsc.stack.mac, dnsc.rhw, dnsc.stack.ip, dnsc.raddr.As4(), ipv4ToS, payload, dnsc.lport, dns.ServerPort)
	dnsc.pkt.PutHeaders(dst)

	return 0, nil
}

func (dnsc *DNSClient) recv(pkt *UDPPacket) error {
	if dnsc.state == dnsAborted {
		return io.EOF
	} else if dnsc.state != dnsAwaitResponse {
		return nil
	}
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
		txid:  dnsc.txid,
	}
	dnsc.msg.Reset()
}

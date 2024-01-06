package stacks

import (
	"errors"
	"io"
	"log/slog"
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
	msg   dns.Message
	raddr netip.Addr
	rhw   [6]byte
	txid  uint16
	lport uint16
	state uint8
	// enables server side recursion.
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
	dnsc.rhw = cfg.DNSHWAddr
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
	payload, err = msg.AppendTo(dst[payloadOffset:payloadOffset])
	if err != nil {
		return 0, err
	} else if len(payload) != int(msgLen) {
		dnsc.stack.error("dns:unexpectedwrite", slog.Int("plen", len(payload)), slog.Uint64("msgLen", uint64(msgLen)))
		return 0, errors.New("dns: unexpected write")
	}
	const ipv4ToS = 0
	setUDP(&dnsc.pkt, dnsc.stack.mac, dnsc.rhw, dnsc.stack.ip, dnsc.raddr.As4(), ipv4ToS, payload, dnsc.lport, dns.ServerPort)
	dnsc.pkt.PutHeaders(dst)
	dnsc.state = dnsAwaitResponse
	return payloadOffset + int(msgLen), nil
}

func (dnsc *DNSClient) recv(pkt *UDPPacket) error {
	if dnsc.state == dnsAborted {
		return io.EOF
	} else if dnsc.state != dnsAwaitResponse {
		return nil
	}
	payload := pkt.Payload()
	if len(payload) < dns.SizeHeader {
		return io.ErrShortBuffer
	}
	dhdr := dns.DecodeHeader(payload)
	if dhdr.TransactionID != dnsc.txid || !dhdr.Flags.IsResponse() {
		dnsc.stack.trace("dns:badResp",
			slog.Uint64("gotTx", uint64(dhdr.TransactionID)),
			slog.Uint64("wantTx", uint64(dnsc.txid)),
		)
		return nil // Does not correspond to our transaction or is not expected server response.
	}
	// Gotten to this point we have a response, valid or not.
	flags := dhdr.Flags
	rcode := flags.ResponseCode()
	dnsc.stack.info("dns:recv", slog.String("op", flags.OpCode().String()), slog.String("rcode", rcode.String()))
	dnsc.state = dnsDone
	if rcode != dns.RCodeSuccess {
		dnsc.msg.Header = dhdr // Used in IsDone.
		return nil
	}

	msg := &dnsc.msg
	_, incompleteButOK, err := msg.Decode(payload)
	if err != nil && !incompleteButOK {
		return err
	} else if incompleteButOK && err != nil {
		dnsc.stack.info("dns:incomplete", slog.String("err", err.Error()))
	}
	return nil
}

func (dnsc *DNSClient) isPendingHandling() bool {
	return dnsc.state == dnsSendQuery || dnsc.state == dnsAborted
}

func (dnsc *DNSClient) IsDone() (bool, dns.RCode) {
	return dnsc.state == dnsDone, dnsc.msg.Header.Flags.ResponseCode()
}

func (dnsc *DNSClient) Answers() []dns.Resource {
	if dnsc.state != dnsDone {
		return nil
	}
	return dnsc.msg.Answers
}

func (dnsc *DNSClient) Abort() {
	if dnsc.state != dnsClosed {
		dnsc.state = dnsAborted
		dnsc.stack.FlagPendingUDP(dnsc.lport)
	}
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

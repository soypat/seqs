package stacks

import (
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/eth/ntp"
)

const (
	ntpClosed = iota
	ntpSend1
	ntpAwait1
	ntpSend2
	ntpAwait2
	ntpDone
)

type NTPClient struct {
	stack *PortStack
	t     [4]ntp.Timestamp
	org   ntp.Timestamp
	rec   ntp.Timestamp
	xmt   ntp.Timestamp
	// The local port to use for sending/receiving NTP packets.
	lport      uint16
	notAborted bool
	pkt        UDPPacket
	state      uint8
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

func (nc *NTPClient) BeginDefaultRequest(raddr netip.Addr) error {
	err := nc.stack.OpenUDP(nc.lport, nc)
	if err != nil {
		return err
	}
	err = nc.stack.FlagPendingUDP(nc.lport)
	if err != nil {
		return err
	}
	nc.notAborted = true
	nc.state = ntpSend1
	return nil
}

func (nc *NTPClient) countNonzero() (s uint8) {
	for i := range nc.t {
		if !nc.t[i].IsZero() {
			s++
		}
	}
	return s
}

func (nc *NTPClient) send(dst []byte) (n int, err error) {
	const (
		payloadoffset = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
		ToS           = 192
	)
	payload := dst[payloadoffset : payloadoffset+ntp.SizeHeader]
	nz := nc.countNonzero()
	if nc.isAborted() || nz == 4 {
		return 0, io.EOF
	}
	sysprec := ntp.SystemPrecision()
	now, err := ntp.TimestampFromTime(nc.stack.now())
	if err != nil {
		return 0, err
	}
	hdr := ntp.Header{
		Stratum:    ntp.StratumUnsync,
		Poll:       6,
		Precision:  sysprec,
		OriginTime: now,
	}
	switch nc.state {
	case ntpSend1:
		nc.xmt = now
		nc.state = ntpAwait1
	case ntpSend2:
		nc.state = ntpDone
	}

	hdr.Put(payload)
	broadcast := eth.BroadcastHW6()
	setUDP(&nc.pkt, nc.stack.mac, broadcast, nc.stack.ip, [4]byte(broadcast[:4]), ToS, payload, nc.lport, ntp.ServerPort)
	nc.pkt.PutHeaders(dst)
	return payloadoffset + ntp.SizeHeader, nil
}

func (nc *NTPClient) recv(pkt *UDPPacket) (err error) {
	payload := pkt.Payload()
	if len(payload) < ntp.SizeHeader {
		return errTooShortNTP
	}
	now, _ := ntp.TimestampFromTime(nc.stack.now())
	nhdr := ntp.DecodeHeader(payload)

	nc.stack.info("ntp:recv",
		slog.Time("origin", nhdr.OriginTime.Time()),
		slog.Time("recv", nhdr.ReceiveTime.Time()),
		slog.Time("transmit", nhdr.TransmitTime.Time()),
	)
	t := &nc.t
	switch nc.state {
	case ntpAwait1: // First packet.
		t[0] = nhdr.OriginTime
		t[1] = nhdr.ReceiveTime
		t[2] = nhdr.TransmitTime
		t[3] = now
		if nhdr.TransmitTime == nc.org || nhdr.OriginTime != nc.xmt {
			return errBogusNTP
		}
		nc.state = ntpDone

	case ntpAwait2:

		nc.state = ntpAwait2
	}
	return nil
}

func (nc *NTPClient) abort() {
	*nc = NTPClient{
		stack: nc.stack,
		lport: nc.lport,
	}
}

func (nc *NTPClient) isPendingHandling() bool {
	return !nc.isAborted()
}

func (d *NTPClient) Abort() {
	d.notAborted = false
}

func (d *NTPClient) isAborted() bool { return !d.notAborted }

func (d *NTPClient) IsDone() bool { return d.state == ntpDone }

// Theta returns the estimated time offset between the local clock and the
// server's clock.
func (d *NTPClient) Theta() time.Duration {
	t := &d.t
	return d.stack.timeadd + (t[1].Sub(t[0])+t[2].Sub(t[3]))/2
}

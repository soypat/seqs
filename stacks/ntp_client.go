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
	pkt   UDPPacket
	// The local port to use for sending/receiving NTP packets.
	lport      uint16
	svip       netip.Addr
	svhw       [6]byte
	notAborted bool
	start      time.Time
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

func (nc *NTPClient) BeginDefaultRequest(hwaddr [6]byte, raddr netip.Addr) error {
	if !raddr.IsValid() {
		return errBadAddr
	}
	err := nc.stack.OpenUDP(nc.lport, nc)
	if err != nil {
		return err
	}
	err = nc.stack.FlagPendingUDP(nc.lport)
	if err != nil {
		return err
	}
	nc.svhw = hwaddr
	nc.svip = raddr
	nc.notAborted = true
	nc.state = ntpSend1
	return nil
}

func (nc *NTPClient) send(dst []byte) (n int, err error) {
	const (
		payloadoffset = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
		ToS           = 192
	)
	payload := dst[payloadoffset : payloadoffset+ntp.SizeHeader]
	if nc.isAborted() {
		return 0, io.EOF
	}
	sysprec := ntp.SystemPrecision()
	switch nc.state {
	case ntpSend1:
		nc.start = nc.stack.now()
		nc.xmt = ntp.TimestampFromUint64(0) // Start out with zero time as unsynced.
		nc.state = ntpAwait1
	case ntpSend2:
		nc.xmt = nc.unsyncTimestamp()
		nc.state = ntpDone
	default:
		return 0, nil // Nothing to handle.
	}
	nc.stack.info("ntp:send",
		slog.Time("xmt", nc.xmt.Time()),
	)
	hdr := ntp.Header{
		Stratum:    ntp.StratumUnsync,
		Poll:       6,
		Precision:  sysprec,
		OriginTime: nc.xmt,
	}
	hdr.SetFlags(ntp.ModeClient, ntp.LeapNoWarning)
	hdr.Put(payload)
	setUDP(&nc.pkt, nc.stack.mac, nc.svhw, nc.stack.ip, nc.svip.As4(), ToS, payload, nc.lport, ntp.ServerPort)
	nc.pkt.PutHeaders(dst)
	return payloadoffset + ntp.SizeHeader, nil
}

func (nc *NTPClient) recv(pkt *UDPPacket) (err error) {
	if nc.isAborted() || nc.IsDone() {
		return io.EOF
	}
	payload := pkt.Payload()
	if len(payload) < ntp.SizeHeader {
		return errTooShortNTP
	}

	nhdr := ntp.DecodeHeader(payload)
	now := nc.unsyncTimestamp()
	nc.stack.info("ntp:recv",
		slog.Time("origin", nhdr.OriginTime.Time()),
		slog.Time("recv", nhdr.ReceiveTime.Time()),
		slog.Time("transmit", nhdr.TransmitTime.Time()),
		slog.Time("t4", now.Time()),
	)
	t := &nc.t
	switch nc.state {
	case ntpAwait1: // First packet.
		if nhdr.TransmitTime == nc.org || nhdr.OriginTime != nc.xmt {
			nc.stack.error("ntp:badpacket", slog.Time("hdr.origin", nhdr.OriginTime.Time()), slog.Time("xmt", nc.xmt.Time()))
			return errBogusNTP
		}
		t[0] = nhdr.OriginTime
		t[1] = nhdr.ReceiveTime
		t[2] = nhdr.TransmitTime
		t[3] = now
		nc.state = ntpDone // Finish on first response for now, enough to get good enough estimation.
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
	return (nc.isAborted() && nc.state != 0) || (nc.state == ntpSend1 || nc.state == ntpSend2)
}

func (d *NTPClient) Abort() {
	d.notAborted = false
}

func (d *NTPClient) isAborted() bool { return !d.notAborted }

func (d *NTPClient) IsDone() bool { return d.state == ntpDone }

func (d *NTPClient) unsyncTimestamp() ntp.Timestamp {
	return ntp.TimestampFromUint64(0).Add(d.stack.now().Sub(d.start))
}

// Offset returns the estimated time offset between the local clock and the
// server's clock.
func (d *NTPClient) Offset() time.Duration {
	t := &d.t
	return d.stack.timeadd + t[1].Sub(t[0])/2 + t[2].Sub(t[3])/2
}

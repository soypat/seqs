package stacks_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stacks"
)

func BenchmarkPortStack(b *testing.B) {
	const udpdst = 67
	MAC := [6]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	ps := stacks.NewPortStack(stacks.PortStackConfig{
		MaxOpenPortsUDP: 1,
		MaxOpenPortsTCP: 1,
		MAC:             MAC,
		MTU:             2048,
	})
	addr := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	tcpsock, _ := stacks.NewTCPConn(ps, stacks.TCPConnConfig{})
	err := tcpsock.OpenDialTCP(80, [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}, netip.AddrPortFrom(addr.Next(), 80), 0xbeadfeed)
	if err != nil {
		b.Fatal(err)
	}
	dhcpsock := stacks.NewDHCPClient(ps, udpdst)
	err = dhcpsock.BeginRequest(stacks.DHCPRequestConfig{
		RequestedAddr: addr,
		Xid:           0x2321,
	})
	if err != nil {
		b.Fatal(err)
	}
	srcudp := NewNoisyUDPSource(MAC, addr)
	srcudp.pkt.UDP.DestinationPort = udpdst
	pkt := []byte("hello")
	buf := make([]byte, ps.MTU())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		srcudp.randomizeSource()
		n := srcudp.WritePacket(buf, pkt)
		ps.RecvEth(buf[:n])
	}
}

func NewNoisyUDPSource(macDst [6]byte, ipDst netip.Addr) *NoisyUDPSource {
	n := &NoisyUDPSource{
		rnd: rand.New(rand.NewSource(0)),
	}
	n.pkt.Eth.Destination = macDst
	n.pkt.IP.Destination = ipDst.As4()
	n.pkt.Eth.SizeOrEtherType = uint16(eth.EtherTypeIPv4)
	n.pkt.IP.Protocol = 17
	n.pkt.IP.TTL = 64
	n.pkt.IP.ID = 0xdead
	n.pkt.IP.VersionAndIHL = 5
	return n
}

type NoisyUDPSource struct {
	rnd *rand.Rand
	pkt stacks.UDPPacket
}

func (n *NoisyUDPSource) WritePacket(dst []byte, payload []byte) int {
	n.pkt.IP.TotalLength = uint16(len(payload)) + eth.SizeIPv4Header + eth.SizeUDPHeader
	n.pkt.UDP.Length = uint16(len(payload)) + eth.SizeUDPHeader
	n.pkt.IP.Checksum = n.pkt.IP.CalculateChecksum()
	n.pkt.UDP.Checksum = n.pkt.UDP.CalculateChecksumIPv4(&n.pkt.IP, payload)
	n.pkt.PutHeaders(dst)
	nn := eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader
	copy(dst[nn:], payload)
	return nn + len(payload)
}

func (n *NoisyUDPSource) randomizeSource() {
	v64 := n.rnd.Int63()
	n.pkt.Eth.Source = [6]byte{byte(v64), byte(v64 >> 8), byte(v64 >> 16), byte(v64 >> 24), byte(v64 >> 32), byte(v64 >> 40)}
	n.pkt.IP.Source = [4]byte{byte(v64), byte(v64 >> 8), byte(v64 >> 16), byte(v64 >> 24)}
	n.pkt.UDP.SourcePort = uint16(v64 >> 32)
	n.pkt.IP.ID = uint16(v64) ^ uint16(v64>>16)
}

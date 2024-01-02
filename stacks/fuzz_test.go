package stacks_test

import (
	"errors"
	"math"
	"testing"

	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stacks"
)

func FuzzTCPEstablished(f *testing.F) {
	f.Add(
		uint16(0), // TCP Flags
		uint16(0), // TCP Window
		uint16(0), // TCP Checksum
		uint16(0), // Size of packet.
		uint16(0), // IP Length field.
	)
	const mtu = 2000
	const tcptxbuf = 1000
	const ipwords = 5
	const tcpwords = 5
	const tcpFlagmask uint16 = 0x01ff
	f.Fuzz(func(t *testing.T, flags, wnd, crc, size, iplen uint16) {
		rng := flags ^ wnd ^ crc ^ size ^ iplen
		var buf [mtu]byte
		client, server := createTCPClientServerPair(t, tcptxbuf, tcptxbuf, mtu)
		clStack := client.PortStack()
		svStack := server.PortStack()
		egr := NewExchanger(clStack, svStack)
		egr.DoExchanges(t, exchangesToEstablish)

		// By now we have an established connection between client and server.
		// We're going to try to crash the server. To do this we use the client's TCB
		// to generate an expected packet.
		scb := client.SCB()
		seg, ok := scb.PendingSegment(int(size)) // +1 to ensure we get a pending segment.
		if !ok && size != 0 {
			panic("could not get pending segment in established state")
		}
		ehdr := eth.EthernetHeader{
			Destination:     svStack.HardwareAddr6(),
			Source:          clStack.HardwareAddr6(),
			SizeOrEtherType: uint16(eth.EtherTypeIPv4),
		}
		ihdr := eth.IPv4Header{
			VersionAndIHL: ipwords,
			TotalLength:   ipwords*4 + tcpwords*4 + size,
			ID:            0x1234,
			Checksum:      0, // Calculate CRC below.
			Protocol:      6,
			Source:        clStack.Addr().As4(),
			Destination:   svStack.Addr().As4(),
			TTL:           64,
			ToS:           192,
			Flags:         0,
		}
		ihdr.Checksum = ihdr.CalculateChecksum()
		flags &= tcpFlagmask

		thdr := eth.TCPHeader{
			SourcePort:      client.LocalPort(),
			DestinationPort: server.LocalPort(),
			Seq:             seg.SEQ,
			Ack:             seg.ACK,
			OffsetAndFlags:  [1]uint16{flags | tcpwords<<12},
			WindowSizeRaw:   wnd,
			Checksum:        crc,
		}
		var tcpOptions []byte // No tcp options.
		ihl := ihdr.HeaderLength()
		payload := buf[eth.SizeEthernetHeader+ihl+int(thdr.OffsetInBytes()):]

		correctCRC := rng > math.MaxUint16/2
		if correctCRC {
			// Calculate checksum "correctly" in this case.
			thdr.Checksum = thdr.CalculateChecksumIPv4(&ihdr, tcpOptions, payload)
		}

		ehdr.Put(buf[:])
		ihdr.Put(buf[eth.SizeEthernetHeader:])
		thdr.Put(buf[eth.SizeEthernetHeader+ihl:])
		err := svStack.RecvEth(buf[:])
		if correctCRC && errors.Is(err, stacks.ErrChecksumTCPorUDP) {
			panic("expected correct CRC calculation")
		} else if !correctCRC && err == nil &&
			thdr.Checksum != thdr.CalculateChecksumIPv4(&ihdr, tcpOptions, payload) {
			panic("expected incorrect CRC calculation")
		}
	})
}

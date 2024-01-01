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
	const tcpoff = 5
	const tcpFlagmask uint16 = 0x01ff
	f.Fuzz(func(t *testing.T, flags, wnd, crc, size, iplen uint16) {
		rng := flags ^ wnd ^ crc ^ size ^ iplen
		var buf [mtu]byte
		client, server := createTCPClientServerPair(t, tcptxbuf, tcptxbuf, mtu)
		cstack := client.PortStack()
		svstack := server.PortStack()
		egr := NewExchanger(cstack, svstack)
		egr.DoExchanges(t, exchangesToEstablish)

		// By now we have an established connection between client and server.
		// We're going to try to crash the client.
		scb := client.SCB()
		seg, ok := scb.PendingSegment(int(size) + 1) // +1 to ensure we get a pending segment.
		if !ok {
			panic("could not get pending segment in established state")
		}
		ehdr := eth.EthernetHeader{
			Destination:     svstack.HardwareAddr6(),
			Source:          cstack.HardwareAddr6(),
			SizeOrEtherType: uint16(eth.EtherTypeIPv4),
		}
		ihdr := eth.IPv4Header{
			VersionAndIHL: ipwords,
			TotalLength:   ipwords*4 + eth.SizeTCPHeader + size,
			ID:            0x1234,
			Checksum:      0, // Calculate CRC below.
			Protocol:      6,
			Source:        cstack.Addr().As4(),
			Destination:   svstack.Addr().As4(),
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
			OffsetAndFlags:  [1]uint16{flags | tcpoff<<12},
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
		err := svstack.RecvEth(buf[:])
		if correctCRC && errors.Is(err, stacks.ErrChecksumTCPorUDP) {
			panic("expected correct CRC calculation")
		} else if !correctCRC && err == nil &&
			thdr.Checksum != thdr.CalculateChecksumIPv4(&ihdr, tcpOptions, payload) {
			panic("expected incorrect CRC calculation")
		}
	})
}

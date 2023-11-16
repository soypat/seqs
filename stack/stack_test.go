package stack_test

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stack"
)

func TestStackEstablish(t *testing.T) {
	const (
		clientISS = 100
		clientWND = 1000

		serverISS = 300
		serverWND = 1300
	)

	var (
		macClient = [6]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipClient  = netip.MustParseAddrPort("192.168.1.1:80")
		macServer = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipServer  = netip.MustParseAddrPort("192.168.1.2:80")
	)

	ClientTCB := seqs.ControlBlock{}
	Client := stack.NewStack(stack.StackConfig{
		MAC:         macClient[:],
		IP:          ipClient.Addr().AsSlice(),
		MaxTCPConns: 1,
	})

	err := Client.OpenTCP(ipClient.Port(), func(response []byte, pkt *stack.TCPPacket) (n int, err error) {
		defer func() {
			if n > 0 && err == nil {
				t.Logf("Client sent: %s", pkt.String())
			}
		}()
		if pkt.HasPacket() {
			t.Logf("Client received: %s", pkt.String())
			payload := pkt.Payload()
			err = ClientTCB.Recv(pkt.TCP.Segment(len(payload)))
			if err != nil {
				return 0, err
			}
			segOut, ok := ClientTCB.PendingSegment(0)
			if !ok {
				return 0, nil
			}
			pkt.InvertSrcDest()
			pkt.CalculateHeaders(segOut, nil)
			pkt.PutHeaders(response)
			return 54, nil
		}

		//
		if ClientTCB == (seqs.ControlBlock{}) {
			// Uninitialized TCB, we start the handshake.
			err = ClientTCB.Open(clientISS, serverISS, seqs.StateSynSent)
			if err != nil {
				return 0, err
			}
			outSeg := seqs.Segment{
				SEQ:   clientISS,
				ACK:   0,
				Flags: seqs.FlagSYN,
				WND:   clientWND,
			}
			pkt.Eth.Destination = macServer
			pkt.Eth.Source = macClient
			pkt.Eth.SizeOrEtherType = uint16(eth.EtherTypeIPv4)

			pkt.IP.Destination = ipServer.Addr().As4()
			pkt.IP.Source = ipClient.Addr().As4()

			pkt.TCP.DestinationPort = ipServer.Port()
			pkt.TCP.SourcePort = ipClient.Port()

			pkt.CalculateHeaders(outSeg, nil)
			pkt.PutHeaders(response)
			return 54, ClientTCB.Send(outSeg)
		}

		return 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Client.FlagTCPPending(ipClient.Port())
	if err != nil {
		t.Fatal(err)
	}

	ServerTCB := seqs.ControlBlock{}
	err = ServerTCB.Open(serverISS, clientISS, seqs.StateListen)
	if err != nil {
		t.Fatal(err)
	}
	Server := stack.NewStack(stack.StackConfig{
		MAC:         macServer[:],
		IP:          ipServer.Addr().AsSlice(),
		MaxTCPConns: 1,
	})
	err = Server.OpenTCP(ipServer.Port(), func(response []byte, pkt *stack.TCPPacket) (n int, err error) {
		defer func() {
			if n > 0 && err == nil {
				t.Logf("Server sent: %s", pkt.String())
			}
		}()
		if pkt.HasPacket() {
			t.Logf("Server received: %s", pkt.String())
			payload := pkt.Payload()
			err = ServerTCB.Recv(pkt.TCP.Segment(len(payload)))
			if err != nil {
				return 0, err
			}
			segOut, ok := ServerTCB.PendingSegment(0)
			if !ok {
				return 0, nil
			}
			pkt.InvertSrcDest()
			pkt.CalculateHeaders(segOut, nil)
			pkt.PutHeaders(response)
			return 54, ServerTCB.Send(segOut)
		}
		return 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var pipe [2048]byte
	zeroPipe := func() { pipe = [2048]byte{} }
	sprintErr := func(err error) string {
		return fmt.Sprintf("%v: client=%s server=%s", err, ClientTCB.State(), ServerTCB.State())
	}

	// 3 way handshake needs 3 exchanges to complete.
	const maxExchanges = 3
	loops := 0
	for loops <= maxExchanges {
		loops++
		nc, err := Client.HandleEth(pipe[:])
		if err != nil && !isDroppedPacket(err) {
			t.Fatal("client handle:", sprintErr(err))
		}
		if nc > 0 {
			err = Server.RecvEth(pipe[:nc])
			if err != nil && !isDroppedPacket(err) {
				t.Fatal("sv recv:", sprintErr(err))
			}
			zeroPipe()
		}

		ns, err := Server.HandleEth(pipe[:])
		if err != nil && !isDroppedPacket(err) {
			t.Fatal("sv handle:", sprintErr(err))
		}
		if ns > 0 {
			err = Client.RecvEth(pipe[:ns])
			if err != nil && !isDroppedPacket(err) {
				t.Fatal("client recv:", sprintErr(err))
			}
			zeroPipe()
		}
		if ns == 0 && nc == 0 {
			break // No more data being interchanged.
		}
	}
	if loops > maxExchanges {
		t.Fatal("unending connection established")
	}
	if ClientTCB.State() != seqs.StateEstablished {
		t.Fatal("client not established")
	}
	if ServerTCB.State() != seqs.StateEstablished {
		t.Fatal("server not established")
	}
}

func isDroppedPacket(err error) bool {
	return err != nil && (errors.Is(err, stack.ErrDroppedPacket) || strings.HasPrefix(err.Error(), "drop"))
}

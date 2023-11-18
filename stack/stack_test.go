package stack_test

import (
	"errors"
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
		IP:          ipClient.Addr(),
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

	Server := stack.NewStack(stack.StackConfig{
		MAC:         macServer[:],
		IP:          ipServer.Addr(),
		MaxTCPConns: 1,
	})
	serverTCP, err := stack.ListenTCP(Server, ipServer.Port(), serverISS, serverWND)
	if err != nil {
		t.Fatal(err)
	}

	// 3 way handshake needs 3 exchanges to complete.
	const maxExchanges = 3
	exchanges, dataExchanged := exchangeStacks(t, maxExchanges, Client, Server)
	const expectedData = (eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader) * 4
	if dataExchanged < expectedData {
		t.Fatal("too little data exchanged", dataExchanged, " want>=", expectedData)
	}
	if exchanges >= 4 {
		t.Fatal("too many exchanges for a 3 way handshake")
	}
	if exchanges <= 2 {
		t.Fatal("too few exchanges for a 3 way handshake")
	}
	if ClientTCB.State() != seqs.StateEstablished {
		t.Fatal("client not established")
	}
	if serverTCP.State() != seqs.StateEstablished {
		t.Fatal("server not established")
	}
}

func isDroppedPacket(err error) bool {
	return err != nil && (errors.Is(err, stack.ErrDroppedPacket) || strings.HasPrefix(err.Error(), "drop"))
}

func exchangeStacks(t *testing.T, maxExchanges int, stacks ...*stack.PortStack) (exchanges, totalData int) {
	loops := 0
	var pipe [2048]byte
	zeroPipe := func() { pipe = [2048]byte{} }
	sprintErr := func(err error) string {
		return err.Error()
		// return fmt.Sprintf("%v: client=%s server=%s", err, ClientTCB.State(), ServerTCB.State())
	}
	totalDataSent := 0
	for loops <= maxExchanges {
		loops++
		sent := 0
		for isender := 0; isender < len(stacks); isender++ {
			n, err := stacks[isender].HandleEth(pipe[:])
			if err != nil && !isDroppedPacket(err) {
				t.Fatalf("send[%d]: %s", isender, sprintErr(err))
			}
			sent += n
			for ireceiver := 0; n > 0 && ireceiver < len(stacks); ireceiver++ {
				if ireceiver == isender {
					continue
				}
				err = stacks[ireceiver].RecvEth(pipe[:n])
				if err != nil && !isDroppedPacket(err) {
					t.Fatalf("recv[%d]: %s", ireceiver, sprintErr(err))
				}
			}
			zeroPipe()
		}
		totalDataSent += sent
		if sent == 0 {
			break // No more data being interchanged.
		}
	}
	return loops, totalDataSent
}

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
		ipClient  = netip.MustParseAddrPort("192.168.1.1:1025")
		macServer = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipServer  = netip.MustParseAddrPort("192.168.1.2:80")
	)

	Client := stack.NewPortStack(stack.PortStackConfig{
		MAC:             macClient[:],
		IP:              ipClient.Addr(),
		MaxOpenPortsTCP: 1,
	})
	clientTCP, err := stack.DialTCP(Client, ipClient.Port(), macServer, ipServer, clientISS, clientWND)
	if err != nil {
		t.Fatal(err)
	}
	err = Client.FlagTCPPending(ipClient.Port())
	if err != nil {
		t.Fatal(err)
	}

	Server := stack.NewPortStack(stack.PortStackConfig{
		MAC:             macServer[:],
		IP:              ipServer.Addr(),
		MaxOpenPortsTCP: 1,
	})
	serverTCP, err := stack.ListenTCP(Server, ipServer.Port(), serverISS, serverWND)
	if err != nil {
		t.Fatal(err)
	}

	// 3 way handshake needs 3 exchanges to complete.
	const maxTransactions = 3
	txDone, numBytesSent := txStacks(t, maxTransactions, Client, Server)
	const expectedData = (eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader) * 4
	if numBytesSent < expectedData {
		t.Error("too little data exchanged", numBytesSent, " want>=", expectedData)
	}
	if txDone >= 3 {
		t.Error("too many exchanges for a 3 way handshake")
	} else if txDone <= 1 {
		t.Error("too few exchanges for a 3 way handshake")
	}
	if clientTCP.State() != seqs.StateEstablished {
		t.Error("client not established: got", clientTCP.State(), "want", seqs.StateEstablished)
	}
	if serverTCP.State() != seqs.StateEstablished {
		t.Error("server not established: got", serverTCP.State(), "want", seqs.StateEstablished)
	}
}

func TestStackSendReceive(t *testing.T) {
	const (
		clientISS = 100
		clientWND = 1000

		serverISS = 300
		serverWND = 1300
	)

	var (
		macClient = [6]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipClient  = netip.MustParseAddrPort("192.168.1.1:1025")
		macServer = [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipServer  = netip.MustParseAddrPort("192.168.1.2:80")
	)

	Client := stack.NewPortStack(stack.PortStackConfig{
		MAC:             macClient[:],
		IP:              ipClient.Addr(),
		MaxOpenPortsTCP: 1,
	})
	clientTCP, err := stack.DialTCP(Client, ipClient.Port(), macServer, ipServer, clientISS, clientWND)
	if err != nil {
		t.Fatal(err)
	}
	err = Client.FlagTCPPending(ipClient.Port())
	if err != nil {
		t.Fatal(err)
	}

	Server := stack.NewPortStack(stack.PortStackConfig{
		MAC:             macServer[:],
		IP:              ipServer.Addr(),
		MaxOpenPortsTCP: 1,
	})
	serverTCP, err := stack.ListenTCP(Server, ipServer.Port(), serverISS, serverWND)
	if err != nil {
		t.Fatal(err)
	}

	// 3 way handshake needs2 exchanges to complete.
	txStacks(t, 2, Client, Server)
	if clientTCP.State() != seqs.StateEstablished || serverTCP.State() != seqs.StateEstablished {
		t.Fatal("not established")
	}

}

func isDroppedPacket(err error) bool {
	return err != nil && (errors.Is(err, stack.ErrDroppedPacket) || strings.HasPrefix(err.Error(), "drop"))
}

func txStacks(t *testing.T, maxTransactions int, stacks ...*stack.PortStack) (tx, bytesSent int) {
	var pipe [2048]byte
	zeroPipe := func() { pipe = [2048]byte{} }
	sprintErr := func(err error) (s string) {
		return err.Error()
	}
	for ; tx <= maxTransactions; tx++ {
		sentInTx := 0
		for isend := 0; isend < len(stacks); isend++ {
			n, err := stacks[isend].HandleEth(pipe[:])
			if err != nil && !isDroppedPacket(err) {
				t.Errorf("tx[%d] send[%d]: %s", tx, isend, sprintErr(err))
				return tx, bytesSent
			} else if isDroppedPacket(err) {
				t.Logf("tx[%d] send[%d]: %s", tx, isend, sprintErr(err))
			}
			if n > 0 {
				pkt, err := stack.ParseTCPPacket(pipe[:n])
				if err != nil {
					t.Errorf("tx[%d] send[%d]: malformed packet: %v", tx, isend, sprintErr(err))
					return tx, bytesSent
				}
				t.Logf("tx[%d] send[%d]: %+v", tx, isend, pkt.TCP.Segment(len(pkt.Payload())))
			}
			bytesSent += n
			sentInTx += n
			for irecv := 0; n > 0 && irecv < len(stacks); irecv++ {
				if irecv == isend {
					continue // Don't send to self!
				}
				err = stacks[irecv].RecvEth(pipe[:n])
				if err != nil && !isDroppedPacket(err) {
					t.Errorf("tx[%d] recv[%d]: %s", tx, irecv, sprintErr(err))
					return tx, bytesSent
				} else if isDroppedPacket(err) {
					t.Logf("tx[%d] recv[%d]: %s", tx, irecv, sprintErr(err))
				}
			}
			zeroPipe()
		}
		if sentInTx == 0 {
			break // No more data being interchanged.
		}
	}
	return tx, bytesSent
}

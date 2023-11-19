package stack_test

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stack"
)

func TestStackEstablish(t *testing.T) {
	client, server := createTCPClientServerPair(t)
	// 3 way handshake needs 3 exchanges to complete.
	const maxTransactions = 3
	txDone, numBytesSent := txStacks(t, maxTransactions, client.PortStack(), server.PortStack())
	const expectedData = (eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader) * 4
	if numBytesSent < expectedData {
		t.Error("too little data exchanged", numBytesSent, " want>=", expectedData)
	}
	if txDone >= 3 {
		t.Error("too many exchanges for a 3 way handshake")
	} else if txDone <= 1 {
		t.Error("too few exchanges for a 3 way handshake")
	}
	if client.State() != seqs.StateEstablished {
		t.Error("client not established: got", server.State(), "want", seqs.StateEstablished)
	}
	if server.State() != seqs.StateEstablished {
		t.Error("server not established: got", server.State(), "want", seqs.StateEstablished)
	}
}

func TestStackSendReceive(t *testing.T) {
	client, server := createTCPClientServerPair(t)

	// 3 way handshake needs2 exchanges to complete.
	txStacks(t, 2, client.PortStack(), server.PortStack())
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatal("not established")
	}

	// Send data from client to server.
	const data = "hello world"
	err := client.Send([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	txStacks(t, 1, client.PortStack(), server.PortStack())
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatal("not established")
	}
	var buf [len(data)]byte
	n, err := server.Recv(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != data {
		t.Error("got", string(buf[:n]), "want", data)
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

func createTCPClientServerPair(t *testing.T) (client, server *stack.TCPSocket) {
	const (
		clientPort = 1025
		clientISS  = 100
		clientWND  = 1000

		serverPort = 80
		serverISS  = 300
		serverWND  = 1300
	)
	stacks := createPortStacks(t, 2)
	clientStack := stacks[0]
	serverStack := stacks[1]

	// Configure server
	serverIP := netip.AddrPortFrom(serverStack.IP, serverPort)
	serverTCP, err := stack.ListenTCP(serverStack, serverIP.Port(), serverISS, serverWND)
	if err != nil {
		t.Fatal(err)
	}

	// Configure client.
	clientTCP, err := stack.DialTCP(clientStack, clientPort, stacks[1].MACAs6(), serverIP, clientISS, clientWND)
	if err != nil {
		t.Fatal(err)
	}
	err = clientStack.FlagTCPPending(clientPort)
	if err != nil {
		t.Fatal(err)
	}

	return clientTCP, serverTCP
}

func createPortStacks(t *testing.T, n int) (stacks []*stack.PortStack) {
	if n > math.MaxUint16 {
		t.Fatal("too many stacks")
	}
	for i := 0; i < n; i++ {
		u8 := [2]uint8{uint8(i) + 1, uint8(i>>8) + 1}
		MAC := [6]byte{0: u8[0], 1: u8[1]}
		ip := netip.AddrFrom4([4]byte{192, 168, u8[1], u8[0]})
		Stack := stack.NewPortStack(stack.PortStackConfig{
			MAC:             MAC,
			IP:              ip,
			MaxOpenPortsTCP: 1,
		})
		stacks = append(stacks, Stack)
	}
	return stacks
}

package stack_test

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stack"
)

const exchangesToEstablish = 4

func TestARP(t *testing.T) {
	const networkSize = 20 // How many distinct IP/MAC addresses on network.
	stacks := createPortStacks(t, networkSize)

	sender := stacks[0]
	target := stacks[1]
	const expectedARP = eth.SizeEthernetHeader + eth.SizeARPv4Header
	// Send ARP request from sender to target.
	sender.BeginResolveARPv4(target.IP.As4())
	ex, n := exchangeStacks(t, 1, stacks...)
	if n != expectedARP {
		t.Errorf("ex[%d] sent=%d want=%d", ex, n, expectedARP)
	}
	// Target responds to sender.
	ex, n = exchangeStacks(t, 1, stacks...)
	if n != expectedARP {
		t.Errorf("ex[%d] sent=%d want=%d", ex, n, expectedARP)
	}

	result, ok := sender.ARPv4Result()
	if !ok {
		t.Fatal("no ARP result")
	}
	if result.HardwareTarget != target.MACAs6() {
		t.Errorf("result.HardwareTarget=%s want=%s", result.HardwareTarget, target.MACAs6())
	}
	if result.ProtoTarget != target.IP.As4() {
		t.Errorf("result.ProtoTarget=%s want=%s", result.ProtoTarget, target.IP.As4())
	}

	// No more data to exchange.
	ex, n = exchangeStacks(t, 1, stacks...)
	if n != 0 {
		t.Fatalf("ex[%d] sent=%d want=0", ex, n)
	}
}

func TestTCPEstablish(t *testing.T) {
	client, server := createTCPClientServerPair(t)

	// 3 way handshake needs 3 exchanges to complete.
	const maxTransactions = exchangesToEstablish + 1
	txDone, numBytesSent := exchangeStacks(t, maxTransactions, client.PortStack(), server.PortStack())

	const expectedData = (eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader) * 4
	if numBytesSent < expectedData {
		t.Error("too little data exchanged", numBytesSent, " want>=", expectedData)
	}
	if txDone > exchangesToEstablish {
		t.Errorf("too many exchanges for a 3 way handshake: got %d want %d", txDone, exchangesToEstablish)
	} else if txDone < exchangesToEstablish {
		t.Errorf("too few exchanges for a 3 way handshake: got %d want %d", txDone, exchangesToEstablish)
	}
	if client.State() != seqs.StateEstablished {
		t.Errorf("client not established: got %s want %s", client.State(), seqs.StateEstablished)
	}
	if server.State() != seqs.StateEstablished {
		t.Errorf("server not established: got %s want %s", server.State(), seqs.StateEstablished)
	}
}

func TestTCPSendReceive_simplex(t *testing.T) {
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t)
	exchangeStacks(t, exchangesToEstablish, client.PortStack(), server.PortStack())
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatal("not established")
	}

	// Send data from client to server.
	const data = "hello world"
	socketSendString(client, data)
	exchangeStacks(t, 2, client.PortStack(), server.PortStack())
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}
	got := socketReadAllString(server)
	if got != data {
		t.Errorf("server: got %q want %q", got, data)
	}
}

func TestTCPSendReceive_duplex_single(t *testing.T) {
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t)
	cstack, sstack := client.PortStack(), server.PortStack()
	exchangeStacks(t, exchangesToEstablish, cstack, sstack)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	// Send data from client to server.
	const data = "hello world"
	socketSendString(client, data)
	socketSendString(server, data)
	tx, bytes := exchangeStacks(t, 2, cstack, sstack)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}
	t.Logf("tx=%d bytes=%d", tx, bytes)
	clientstr := socketReadAllString(client)
	serverstr := socketReadAllString(server)
	if clientstr != data {
		t.Errorf("client: got %q want %q", clientstr, data)
	}
	if serverstr != data {
		t.Errorf("server: got %q want %q", serverstr, data)
	}
}

func TestTCPSendReceive_duplex(t *testing.T) {
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t)
	cstack, sstack := client.PortStack(), server.PortStack()
	exchangeStacks(t, exchangesToEstablish, cstack, sstack)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	// Send data from client to server multiple times.
	const messages = 1024
	for i := 0; i < messages; i++ {
		cdata := fmt.Sprintf("hello world %d", i)
		sdata := fmt.Sprintf("hello yourself %d", i)

		socketSendString(client, cdata)
		socketSendString(server, sdata)
		tx, bytes := exchangeStacks(t, 2, cstack, sstack)
		if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
			t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
		}
		t.Logf("tx=%d bytes=%d", tx, bytes)
		clientstr := socketReadAllString(client)
		serverstr := socketReadAllString(server)
		if clientstr != sdata {
			t.Errorf("client: got %q want %q", clientstr, sdata)
		}
		if serverstr != cdata {
			t.Errorf("server: got %q want %q", serverstr, cdata)
		}
	}
}

func TestTCPClose_noPendingData(t *testing.T) {
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t)
	cstack, sstack := client.PortStack(), server.PortStack()
	exchangeStacks(t, exchangesToEstablish, cstack, sstack)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	err := client.Close()
	if err != nil {
		t.Fatalf("client.Close(): %v", err)
	}
	i := 0
	doExpect := func(t *testing.T, maxExchanges int, wantClient, wantServer seqs.State) {
		t.Helper()
		_, transmitted := exchangeStacks(t, maxExchanges, cstack, sstack)
		if client.State() != wantClient || server.State() != wantServer {
			t.Fatalf("do[%d] sent %d\nwant client=%s server=%s\ngot  client=%s server=%s",
				i, transmitted, wantClient, wantServer, client.State(), server.State())
		}
		i++
	}

	// See RFC 9293 Figure 5: TCP Connection State Diagram.
	doExpect(t, 1, seqs.StateFinWait1, seqs.StateEstablished) // do[0] Client sends FIN.
	doExpect(t, 1, seqs.StateFinWait1, seqs.StateCloseWait)   // do[1] Server sends ACK after receiving FIN.
	doExpect(t, 1, seqs.StateFinWait2, seqs.StateLastAck)     // do[2] Server sends FIN|ACK, client parses ACK->FinWait2.
	doExpect(t, 1, seqs.StateTimeWait, seqs.StateClosed)      // do[3] Cliend sends ACK after receiving FIN, connection terminated.
}

// exchangeStacks exchanges packets between stacks until no more data is being sent or maxExchanges is reached.
// By convention client (initiator) is the first stack and server (listener) is the second when dealing with pairs.
func exchangeStacks(t *testing.T, maxExchanges int, stacks ...*stack.PortStack) (ex, bytesSent int) {
	t.Helper()
	sprintErr := func(err error) (s string) {
		return err.Error()
	}
	pipeN := make([]int, len(stacks))
	pipes := make([][2048]byte, len(stacks))
	zeroPayload := func(i int) {
		pipeN[i] = 0
		pipes[i] = [2048]byte{}
	}
	getPayload := func(i int) []byte { return pipes[i][:pipeN[i]] }
	var err error
	// Short hand for debug conditions. I've found setting ME==n be a good breakpoint condition since
	// we'll usually have several exchangeStacks calls in a test with varying maxExchanges. Helps skip connection establishments and other events.
	var ME = maxExchanges
	for ; ex < ME; ex++ {
		sentInTx := 0
		for isend := 0; isend < len(stacks); isend++ {
			// This first for loop generates packets "in-flight" contained in `pipes` data structure.
			pipeN[isend], err = stacks[isend].HandleEth(pipes[isend][:])
			if (err != nil && !isDroppedPacket(err)) || pipeN[isend] < 0 {
				t.Errorf("ex[%d] send[%d]: %s", ex, isend, sprintErr(err))
				return ex, bytesSent
			} else if isDroppedPacket(err) {
				t.Logf("ex[%d] send[%d]: %s", ex, isend, sprintErr(err))
			}
			if pipeN[isend] > 0 {
				pkt, err := stack.ParseTCPPacket(getPayload(isend))
				if err == nil {
					t.Logf("ex[%d] send[%d]: %+v", ex, isend, pkt.TCP.Segment(len(pkt.Payload())))
				}
			}
			bytesSent += pipeN[isend]
			sentInTx += pipeN[isend]
		}
		if sentInTx == 0 {
			break // No more data being sent.
		}
		for isend := 0; isend < len(stacks); isend++ {
			// We deliver each in-flight packet to all stacks, except the one that sent it.
			payload := getPayload(isend)
			if len(payload) == 0 {
				continue
			}
			for irecv := 0; irecv < len(stacks); irecv++ {
				if irecv == isend {
					continue // Don't deliver to self.
				}
				err = stacks[irecv].RecvEth(payload)
				if err != nil && !isDroppedPacket(err) {
					t.Errorf("ex[%d] recv[%d]: %s", ex, irecv, sprintErr(err))
					return ex, bytesSent
				} else if isDroppedPacket(err) {
					t.Logf("ex[%d] recv[%d]: %s", ex, irecv, sprintErr(err))
				}
			}
			zeroPayload(isend)
		}
	}
	return ex, bytesSent
}

func isDroppedPacket(err error) bool {
	return err != nil && (errors.Is(err, stack.ErrDroppedPacket) || strings.HasPrefix(err.Error(), "drop"))
}

func createTCPClientServerPair(t *testing.T) (client, server *stack.TCPSocket) {
	t.Helper()
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
	t.Helper()
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

func socketReadAllString(s *stack.TCPSocket) string {
	var str strings.Builder
	var buf [1024]byte
	for {
		n, err := s.Recv(buf[:])
		str.Write(buf[:n])
		if n == 0 || err != nil {
			break
		}
	}
	return str.String()
}

func socketSendString(s *stack.TCPSocket, str string) {
	err := s.Send([]byte(str))
	if err != nil {
		panic(err)
	}
}

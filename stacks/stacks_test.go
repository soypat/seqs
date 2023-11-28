package stacks_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stacks"
)

const (
	testingLargeNetworkSize = 2 // Minimum=2
	exchangesToEstablish    = 4
)

func TestDHCP(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	requestedIP := netip.AddrFrom4([4]byte{192, 168, 1, 69})
	Stacks := createPortStacks(t, networkSize)
	clientStack := Stacks[0]
	serverStack := Stacks[1]

	client := stacks.DHCPv4Client{
		MAC:         clientStack.MACAs6(),
		RequestedIP: requestedIP.As4(),
	}
	server := stacks.NewDHCPServer(67, serverStack.MACAs6(), serverStack.Addr())
	clientStack.SetAddr(netip.AddrFrom4([4]byte{}))
	serverStack.SetAddr(netip.AddrFrom4([4]byte{}))
	err := clientStack.OpenUDP(68, client.HandleUDP)
	if err != nil {
		t.Fatal(err)
	}
	err = clientStack.FlagPendingUDP(68) // Force a DHCP discovery.
	if err != nil {
		t.Fatal(err)
	}
	err = serverStack.OpenUDP(67, server.HandleUDP)
	if err != nil {
		t.Fatal(err)
	}
	const minDHCPSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader + eth.SizeDHCPHeader
	// Client performs DISCOVER.
	ex, n := exchangeStacks(t, 1, Stacks...)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	if client.Done() {
		t.Fatal("client done on first exchange?!")
	}

	// Server responds with OFFER.
	ex, n = exchangeStacks(t, 1, Stacks...)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}

	// Client performs REQUEST.
	ex, n = exchangeStacks(t, 1, Stacks...)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	if client.Done() {
		t.Fatal("client done on request?!")
	}

	// Server performs ACK.
	ex, n = exchangeStacks(t, 1, Stacks...)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	if client.Done() {
		t.Fatal("client not processed ACK yet")
	}

	// Client processes ACK
	exchangeStacks(t, 1, Stacks...)
	if !client.Done() {
		t.Fatal("client should be done")
	}
}

func TestARP(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	stacks := createPortStacks(t, networkSize)

	sender := stacks[0]
	target := stacks[1]
	const expectedARP = eth.SizeEthernetHeader + eth.SizeARPv4Header
	// Send ARP request from sender to target.
	sender.BeginResolveARPv4(target.Addr().As4())
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
		t.Fatal("no ARP result", result.HardwareSender)
	}
	if result.HardwareSender != target.MACAs6() {
		t.Errorf("result.HardwareSender=%s want=%s", result.HardwareSender, target.MACAs6())
	}
	if result.ProtoSender != target.Addr().As4() {
		t.Errorf("result.ProtoSender=%s want=%s", result.ProtoSender, target.Addr().As4())
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
	const maxTransactions = exchangesToEstablish
	txDone, numBytesSent := exchangeStacks(t, maxTransactions, client.PortStack(), server.PortStack())

	_, remnant := exchangeStacks(t, 1, client.PortStack(), server.PortStack())
	if remnant != 0 {
		// TODO(soypat): prevent duplicate ACKs from being sent.
		// t.Fatalf("duplicate ACK detected? remnant=%d want=0", remnant)
	}

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

func TestPortStackTCPDecoding(t *testing.T) {
	const dataport = 1234
	packets := []string{
		"28cdc1054d3ed85ed34303eb08004500003c76eb400040063f76c0a80192c0a80178ee1604d2a0ceb98a00000000a002faf06e800000020405b40402080a14ccf8250000000001030307",
	}
	var handleBuf [2048]byte
	for _, data := range packets {
		data, _ := hex.DecodeString(data)
		ehdr := eth.DecodeEthernetHeader(data)
		ps := stacks.NewPortStack(stacks.PortStackConfig{
			MaxOpenPortsTCP: 1,
			MTU:             2048,
			MAC:             ehdr.Destination,
		})
		var got stacks.TCPPacket
		err := ps.OpenTCP(dataport, func(_ []byte, pkt *stacks.TCPPacket) (int, error) {
			got = *pkt
			return 0, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// We recv eth and handle eth so that our callback runs.
		err = ps.RecvEth(data)
		if err != nil {
			t.Fatal(err)
		}

		n, err := ps.HandleEth(handleBuf[:])
		if err != nil {
			t.Fatal(err)
		} else if n != 0 {
			t.Errorf("n=%d want=0", n)
		}
		if !got.HasPacket() {
			t.Fatal("no packet")
		}
		gotTCPOptions := got.TCPOptions()
		gotIPOptions := got.IPOptions()
		gotPayload := got.Payload()
		gotsum := got.TCP.CalculateChecksumIPv4(&got.IP, gotTCPOptions, gotPayload)

		pkt, err := stacks.ParseTCPPacket([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		wantTCPOptions := pkt.TCPOptions()
		wantIPOptions := pkt.IPOptions()
		wantPayload := pkt.Payload()
		wantsum := pkt.TCP.CalculateChecksumIPv4(&pkt.IP, wantTCPOptions, wantPayload)
		if !bytes.Equal(gotTCPOptions, wantTCPOptions) {
			t.Errorf("gotTCPOptions=%x want=%x", gotTCPOptions, wantTCPOptions)
		}
		if !bytes.Equal(gotIPOptions, wantIPOptions) {
			t.Errorf("gotIPOptions=%x want=%x", gotIPOptions, wantIPOptions)
		}
		if !bytes.Equal(gotPayload, wantPayload) {
			t.Errorf("gotPayload=%x want=%x", gotPayload, wantPayload)
		}
		if gotsum != wantsum {
			t.Errorf("gotsum=%x want=%x", gotsum, wantsum)
		}
		if gotsum != got.TCP.Checksum {
			t.Errorf("gotsum=%x want=%x", gotsum, got.TCP.Checksum)
		}
	}
}

// exchangeStacks exchanges packets between stacks until no more data is being sent or maxExchanges is reached.
// By convention client (initiator) is the first stack and server (listener) is the second when dealing with pairs.
func exchangeStacks(t *testing.T, maxExchanges int, stcks ...*stacks.PortStack) (ex, bytesSent int) {
	t.Helper()
	sprintErr := func(err error) (s string) {
		return err.Error()
	}
	pipeN := make([]int, len(stcks))
	pipes := make([][2048]byte, len(stcks))
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
		for isend := 0; isend < len(stcks); isend++ {
			// This first for loop generates packets "in-flight" contained in `pipes` data structure.
			pipeN[isend], err = stcks[isend].HandleEth(pipes[isend][:])
			if (err != nil && !isDroppedPacket(err)) || pipeN[isend] < 0 {
				t.Errorf("ex[%d] send[%d]: %s", ex, isend, sprintErr(err))
				return ex, bytesSent
			} else if isDroppedPacket(err) {
				t.Logf("ex[%d] send[%d]: %s", ex, isend, sprintErr(err))
			}
			if pipeN[isend] > 0 {
				pkt, err := stacks.ParseTCPPacket(getPayload(isend))
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

		for isend := 0; isend < len(stcks); isend++ {
			// We deliver each in-flight packet to all stacks, except the one that sent it.
			payload := getPayload(isend)
			if len(payload) == 0 {
				continue
			}
			for irecv := 0; irecv < len(stcks); irecv++ {
				if irecv == isend {
					continue // Don't deliver to self.
				}
				err = stcks[irecv].RecvEth(payload)
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
	return err != nil && (errors.Is(err, stacks.ErrDroppedPacket) || strings.HasPrefix(err.Error(), "drop"))
}

func createTCPClientServerPair(t *testing.T) (client, server *stacks.TCPSocket) {
	t.Helper()
	const (
		clientPort = 1025
		clientISS  = 100
		clientWND  = 1000

		serverPort = 80
		serverISS  = 300
		serverWND  = 1300
	)
	Stacks := createPortStacks(t, 2)
	clientStack := Stacks[0]
	serverStack := Stacks[1]

	// Configure server
	serverIP := netip.AddrPortFrom(serverStack.Addr(), serverPort)

	serverTCP, err := stacks.NewTCPSocket(serverStack, stacks.TCPSocketConfig{
		TxBufSize: 2048,
		RxBufSize: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = serverTCP.OpenListenTCP(serverIP.Port(), serverISS)
	// serverTCP, err := stacks.ListenTCP(serverStack, serverIP.Port(), serverISS, serverWND)
	if err != nil {
		t.Fatal(err)
	}

	// Configure client.
	clientTCP, err := stacks.NewTCPSocket(clientStack, stacks.TCPSocketConfig{
		TxBufSize: 2048,
		RxBufSize: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = clientTCP.OpenDialTCP(clientPort, serverStack.MACAs6(), serverIP, clientISS)
	// clientTCP, err := stacks.DialTCP(clientStack, clientPort, Stacks[1].MACAs6(), serverIP, clientISS, clientWND)
	if err != nil {
		t.Fatal(err)
	}
	err = clientStack.FlagPendingTCP(clientPort)
	if err != nil {
		t.Fatal(err)
	}

	return clientTCP, serverTCP
}

func createPortStacks(t *testing.T, n int) (Stacks []*stacks.PortStack) {
	t.Helper()
	if n > math.MaxUint16 {
		t.Fatal("too many stacks")
	}
	for i := 0; i < n; i++ {
		u8 := [2]uint8{uint8(i) + 1, uint8(i>>8) + 1}
		MAC := [6]byte{0: u8[0], 1: u8[1]}
		ip := netip.AddrFrom4([4]byte{192, 168, u8[1], u8[0]})
		Stack := stacks.NewPortStack(stacks.PortStackConfig{
			MAC:             MAC,
			MaxOpenPortsTCP: 1,
			MaxOpenPortsUDP: 1,
			MTU:             2048,
		})
		Stack.SetAddr(ip)
		Stacks = append(Stacks, Stack)
	}
	return Stacks
}

func socketReadAllString(s *stacks.TCPSocket) string {
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

func socketSendString(s *stacks.TCPSocket, str string) {
	err := s.Send([]byte(str))
	if err != nil {
		panic(err)
	}
}

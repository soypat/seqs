package stacks_test

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
	"github.com/soypat/seqs/stacks"
)

const (
	testingLargeNetworkSize = 2 // Minimum=2
	exchangesToEstablish    = 3
	exchangesToClose        = 4
	defaultTCPBufferSize    = 2048
)

func TestDHCP(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	requestedIP := netip.AddrFrom4([4]byte{192, 168, 1, 69})
	siaddr := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	Stacks := createPortStacks(t, networkSize)

	clientStack := Stacks[0]
	serverStack := Stacks[1]

	clientStack.SetAddr(netip.AddrFrom4([4]byte{}))
	serverStack.SetAddr(netip.AddrFrom4([4]byte{}))

	client := stacks.NewDHCPClient(clientStack, 68)
	server := stacks.NewDHCPServer(serverStack, siaddr, 67)
	err := client.BeginRequest(stacks.DHCPRequestConfig{
		RequestedAddr: requestedIP,
		Xid:           0x12345678,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Start()
	if err != nil {
		t.Fatal(err)
	}

	const minDHCPSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader + eth.SizeDHCPHeader
	// Client performs DISCOVER.
	egr := NewExchanger(clientStack, serverStack)
	ex, n := egr.DoExchanges(t, 1)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	if client.Done() {
		t.Fatal("client done on first exchange?!")
	}

	// Server responds with OFFER.
	ex, n = egr.DoExchanges(t, 1)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	t.Logf("\nclient=%+v\nserver=%+v\n", client, server)
	// Client performs REQUEST.
	ex, n = egr.DoExchanges(t, 1)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	if client.Done() {
		t.Fatal("client done on request?!")
	}

	// Server performs ACK; client processes ACK
	ex, n = egr.DoExchanges(t, 1)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	if !client.Done() {
		t.Fatal("client not processed ACK yet")
	}

}

func TestARP(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	stacks := createPortStacks(t, networkSize)

	sender := stacks[0]
	target := stacks[1]
	const expectedARP = eth.SizeEthernetHeader + eth.SizeARPv4Header
	// Send ARP request from sender to target.
	sender.ARP().BeginResolve(target.Addr())
	egr := NewExchanger(stacks...)
	ex, n := egr.DoExchanges(t, 1)
	if n != expectedARP {
		t.Errorf("ex[%d] sent=%d want=%d", ex, n, expectedARP)
	}
	// Target responds to sender.
	ex, n = egr.DoExchanges(t, 1)
	if n != expectedARP {
		t.Errorf("ex[%d] sent=%d want=%d", ex, n, expectedARP)
	}

	ip, mac, err := sender.ARP().ResultAs6()
	if err != nil {
		t.Fatal(err)
	}
	if !ip.IsValid() {
		t.Fatal("invalid IP")
	}
	if mac != target.HardwareAddr6() {
		t.Errorf("result.HardwareSender=%s want=%s", mac, target.HardwareAddr6())
	}
	if ip.As4() != target.Addr().As4() {
		t.Errorf("result.ProtoSender=%s want=%s", ip, target.Addr().As4())
	}

	// No more data to exchange.
	ex, n = egr.DoExchanges(t, 1)
	if n != 0 {
		t.Fatalf("ex[%d] sent=%d want=0", ex, n)
	}
}

func TestTCPEstablish(t *testing.T) {
	client, server := createTCPClientServerPair(t)
	// 3 way handshake needs 3 exchanges to complete.
	const maxTransactions = exchangesToEstablish
	egr := NewExchanger(client.PortStack(), server.PortStack())
	wantStates := func(cs, ss seqs.State) {
		t.Helper()
		if client.State() != cs {
			t.Errorf("client state got=%s want=%s", client.State(), cs)
		}
		if server.State() != ss {
			t.Errorf("server state got=%s want=%s", server.State(), ss)
		}
	}
	// Test initial states.
	wantStates(seqs.StateSynSent, seqs.StateListen)
	txs, n := egr.HandleTx(t)
	if n == 0 {
		t.Fatal("no data sent on first exchange")
	} else if txs != 1 {
		t.Fatal("expected only client's exchange")
	}
	wantStates(seqs.StateSynSent, seqs.StateListen) // Not yet received by server.
	checkNoMoreDataSent(t, "after client SYN", egr)

	egr.HandleRx(t)
	wantStates(seqs.StateSynSent, seqs.StateSynRcvd)

	txs, n = egr.HandleTx(t)
	if n == 0 {
		t.Fatal("no data sent from server in response to syn (SYNACK) exchange")
	} else if txs != 1 {
		t.Fatal("expected only server's exchange")
	}
	wantStates(seqs.StateSynSent, seqs.StateSynRcvd)
	checkNoMoreDataSent(t, "after server SYN|ACK", egr)

	// Client established after receiving SYNACK.
	egr.HandleRx(t)
	wantStates(seqs.StateEstablished, seqs.StateSynRcvd)

	// Client responds with ACK.
	txs, n = egr.HandleTx(t)
	if n == 0 {
		t.Fatal("expected ACK from client; got no data")
	} else if txs != 1 {
		t.Fatal("expected only client's exchange")
	}
	wantStates(seqs.StateEstablished, seqs.StateSynRcvd)
	checkNoMoreDataSent(t, "after server SYN|ACK", egr)

	// Server established after receiving ACK to SYNACK.
	egr.HandleRx(t)
	wantStates(seqs.StateEstablished, seqs.StateEstablished)

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
	egr := NewExchanger(client.PortStack(), server.PortStack())
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatal("not established")
	}

	// Send data from client to server.
	const data = "hello world"
	socketSendString(client, data)
	egr.DoExchanges(t, 2)
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
	egr := NewExchanger(cstack, sstack)
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	// Send data from client to server.
	const data = "hello world"
	socketSendString(client, data)
	socketSendString(server, data)

	tx, bytes := egr.DoExchanges(t, 2)
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
	egr := NewExchanger(client.PortStack(), server.PortStack())
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	// Send data from client to server multiple times.
	testSocketDuplex(t, client, server, egr, 1024)
}

func TestTCPClose_noPendingData(t *testing.T) {
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t)
	egr := NewExchanger(client.PortStack(), server.PortStack())
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}
	_, b := egr.DoExchanges(t, 2)
	if b != 0 {
		t.Fatal("expected no data to be exchanged after establishment")
	}

	err := client.Close()
	if err != nil {
		t.Fatalf("client.Close(): %v", err)
	}
	i := 0
	doExpect := func(t *testing.T, wantClient, wantServer seqs.State, wantFlags seqs.Flags) {
		t.Helper()
		isRx := i%2 == 0
		if isRx {
			pkts, _ := egr.HandleTx(t)
			if pkts == 0 {
				t.Error("no packet")
			}
			lastSeg := egr.LastSegment()
			if wantFlags != 0 && lastSeg.Flags != wantFlags {
				t.Errorf("do[%d] RX=%v\nwant flags=%v\ngot  flags=%v", i, isRx, wantFlags, lastSeg.Flags)
			}
		} else {
			egr.HandleRx(t)
		}
		t.Logf("client=%s server=%s", client.State(), server.State())
		if client.State() != wantClient || server.State() != wantServer {
			t.Fatalf("do[%d] RX=%v\nwant client=%s server=%s\ngot  client=%s server=%s",
				i, isRx, wantClient, wantServer, client.State(), server.State())
		}
		i++
	}
	// See RFC 9293 Figure 5: TCP Connection State Diagram.
	/*
		Figure 12: Normal Close Sequence
		TCP Peer A                                           TCP Peer B
		1.  ESTABLISHED                                          ESTABLISHED

		2.  (Close)
			FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  --> CLOSE-WAIT

		3.  FIN-WAIT-2  <-- <SEQ=300><ACK=101><CTL=ACK>      <-- CLOSE-WAIT

		4.                                                       (Close)
			TIME-WAIT   <-- <SEQ=300><ACK=101><CTL=FIN,ACK>  <-- LAST-ACK

		5.  TIME-WAIT   --> <SEQ=101><ACK=301><CTL=ACK>      --> CLOSED

		6.  (2 MSL)
			CLOSED
	*/
	// Peer A == Client;   Peer B == Server
	const finack = seqs.FlagFIN | seqs.FlagACK
	doExpect(t, seqs.StateFinWait1, seqs.StateEstablished, finack)     // do[0] Client sends FIN|ACK
	doExpect(t, seqs.StateFinWait1, seqs.StateCloseWait, 0)            // do[1] Server receives FINACK, goes into close wait
	doExpect(t, seqs.StateFinWait1, seqs.StateCloseWait, seqs.FlagACK) // do[2] Server sends ACK of client FIN
	doExpect(t, seqs.StateFinWait2, seqs.StateCloseWait, 0)            // do[3] client receives ACK of FIN, goes into finwait2
	doExpect(t, seqs.StateFinWait2, seqs.StateLastAck, finack)         // do[4] Server sends out FIN|ACK and enters LastAck state.
	doExpect(t, seqs.StateTimeWait, seqs.StateClosed, 0)               // do[5] Client receives FIN, prepares to send ACK and enters TimeWait state.
	doExpect(t, seqs.StateClosed, seqs.StateClosed, seqs.FlagACK)      // do[6] Client sends ACK and enters Closed state.
}

func TestTCPSocketOpenOfClosedPort(t *testing.T) {
	// Create Client+Server and establish TCP connection between them.
	const newPortoffset = 1
	const newISS = 1337
	client, server := createTCPClientServerPair(t)
	cstack, sstack := client.PortStack(), server.PortStack()

	egr := NewExchanger(cstack, sstack)
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}
	client.Close()
	egr.DoExchanges(t, exchangesToClose)
	if client.State() != seqs.StateClosed || server.State() != seqs.StateClosed {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	saddrport := netip.AddrPortFrom(sstack.Addr(), server.LocalPort()+newPortoffset)
	err := client.OpenDialTCP(client.LocalPort()+newPortoffset+1, sstack.HardwareAddr6(), saddrport, newISS)
	if err != nil {
		t.Fatal(err)
	}
	err = server.OpenListenTCP(saddrport.Port(), newISS+100)
	if err != nil {
		t.Fatal(err)
	}
	const minBytesToEstablish = (eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeTCPHeader) * exchangesToEstablish
	_, nbytes := egr.DoExchanges(t, exchangesToEstablish)
	if nbytes < minBytesToEstablish {
		t.Fatalf("insufficient data to establish: got %d want>=%d", nbytes, minBytesToEstablish)
	}
	testSocketDuplex(t, client, server, egr, 128)
}

func testSocketDuplex(t *testing.T, client, server *stacks.TCPConn, egr *Exchanger, messages int) {
	t.Helper()
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		panic("not established")
	}
	// Send data from client to server multiple times.
	baseCdata := []byte("from client: hello server ")
	baseSdata := []byte("from server: hello client ")
	for i := 0; i < messages; i++ {
		cdata := strconv.AppendInt(baseCdata, int64(i), 10)
		sdata := strconv.AppendInt(baseSdata, int64(i), 10)
		messagelen := len(cdata) // Same length for both client and server.
		socketSendString(client, string(cdata))
		socketSendString(server, string(sdata))
		prevSegs := len(egr.segments)
		tx, bytes := egr.DoExchanges(t, 1)
		if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
			t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
		}
		totSegments := len(egr.segments) - prevSegs
		if totSegments != 2 {
			t.Errorf("expected 2 segments exchanged, got %d", totSegments)
		} else if messagelen != int(egr.LastSegment().DATALEN) || messagelen != int(egr.SegmentToLast(1).DATALEN) {
			t.Errorf("expected %d bytes exchanged, got %d,%d", messagelen, egr.LastSegment().DATALEN, egr.SegmentToLast(1).DATALEN)
		}
		_, _ = tx, bytes
		// t.Logf("tx=%d bytes=%d", tx, bytes)
		clientstr := socketReadAllString(client)
		serverstr := socketReadAllString(server)
		if clientstr != string(sdata) {
			t.Errorf("client: got %q want %q", clientstr, sdata)
		}
		if serverstr != string(cdata) {
			t.Errorf("server: got %q want %q", serverstr, cdata)
		}
		if t.Failed() {
			return // Return on first error.
		}
	}
}

func TestPortStackTCPDecoding(t *testing.T) {
	const dataport = 1234
	packets := []string{
		"28cdc1054d3ed85ed34303eb08004500003c76eb400040063f76c0a80192c0a80178ee1604d2a0ceb98a00000000a002faf06e800000020405b40402080a14ccf8250000000001030307",
		"28cdc101137c88aedd0a709208004500002db03a4000400675590a0000be0a00007ac7ce04d22a67581700000d535018fa4b0000000068656c6c6f",
	}
	for i, data := range packets {
		data, _ := hex.DecodeString(data)
		ehdr := eth.DecodeEthernetHeader(data)
		ps := stacks.NewPortStack(stacks.PortStackConfig{
			MaxOpenPortsTCP: 1,
			MTU:             2048,
			MAC:             ehdr.Destination,
		})
		sock, err := stacks.NewTCPConn(ps, stacks.TCPConnConfig{})
		if err != nil {
			t.Fatal(i, err)
		}
		err = ps.OpenTCP(dataport, sock)
		if err != nil {
			t.Fatal(i, err)
		}
		err = ps.RecvEth(data)
		if err != nil && !errors.Is(err, stacks.ErrDroppedPacket) {
			t.Fatal(i, err)
		}
	}
}

func TestListener(t *testing.T) {
	client, listener := createTCPClientListenerPair(t)
	egr := NewExchanger(client.PortStack(), listener.PortStack())
	// Establish the connection on one port.
	exdone, _ := egr.DoExchanges(t, exchangesToEstablish)
	if exdone == 0 {
		panic(exdone)
	}
	return
	netconn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	server := netconn.(*stacks.TCPConn)
	if server.State() != seqs.StateEstablished {
		t.Error("expected listener conn to be established")
	}
	if client.State() != seqs.StateEstablished {
		t.Error("expected client conn to be established")
	}
	testSocketDuplex(t, client, server, egr, 1024)
}

type Exchanger struct {
	Stacks   []*stacks.PortStack
	pipesN   []int
	pipes    [][2048]byte
	segments []seqs.Segment
	ex       int
	loglevel slog.Level
}

func NewExchanger(stacks ...*stacks.PortStack) *Exchanger {
	egr := &Exchanger{
		Stacks: stacks,
		pipesN: make([]int, len(stacks)),
		pipes:  make([][2048]byte, len(stacks)),
		ex:     -1,
	}
	return egr
}

func (egr *Exchanger) isdebug() bool { return egr.loglevel <= slog.LevelDebug }
func (egr *Exchanger) isinfo() bool  { return egr.loglevel <= slog.LevelInfo }

// LastSegment returns the last TCP segment sent over the stack.
func (egr *Exchanger) LastSegment() seqs.Segment {
	if len(egr.segments) == 0 {
		return seqs.Segment{}
	}
	return egr.segments[len(egr.segments)-1]
}

// SegmentToLast returns the ith from last TCP segment sent over the stack. When fromLast==0 returns last segment.
func (egr *Exchanger) SegmentToLast(fromLast int) seqs.Segment {
	return egr.segments[len(egr.segments)-fromLast-1]
}

func (egr *Exchanger) getPayload(istack int) []byte {
	return egr.pipes[istack][:egr.pipesN[istack]]
}

func (egr *Exchanger) zeroPayload(istack int) {
	egr.pipesN[istack] = 0
	egr.pipes[istack] = [2048]byte{}
}

// auxbuf returns an unused buffer for temporary use. Do not hold references to this buffer during calls to HandleTx.
func (egr *Exchanger) auxbuf() []byte {
	for istack := 0; istack < len(egr.Stacks); istack++ {
		if egr.pipesN[istack] == 0 {
			return egr.pipes[istack][:]
		}
	}
	return make([]byte, 2048)
}

func (egr *Exchanger) HandleTx(t *testing.T) (pkts, bytesSent int) {
	egr.ex++
	t.Helper()
	var err error
	for istack := 0; istack < len(egr.Stacks); istack++ {
		// This first for loop generates packets "in-flight" contained in `pipes` data structure.
		egr.pipesN[istack], err = egr.Stacks[istack].HandleEth(egr.pipes[istack][:])
		if (err != nil && !isDroppedPacket(err)) || egr.pipesN[istack] < 0 {
			t.Errorf("ex[%d] send[%d]: %s", egr.ex, istack, err)
			return pkts, bytesSent
		} else if isDroppedPacket(err) && egr.isdebug() {
			t.Logf("ex[%d] send[%d]: %s", egr.ex, istack, err)
		}
		if egr.pipesN[istack] > 0 {
			pkts++
			pkt, err := stacks.ParseTCPPacket(egr.getPayload(istack))
			if err == nil {
				seg := pkt.TCP.Segment(len(pkt.Payload()))
				egr.segments = append(egr.segments, seg)
				if egr.isdebug() {
					t.Logf("ex[%d] send[%d]: %+v", egr.ex, istack, seg)
				}
			}
		}
		bytesSent += egr.pipesN[istack]
	}
	return pkts, bytesSent
}

func (egr *Exchanger) HandleRx(t *testing.T) {
	var err error
	for isend := 0; isend < len(egr.Stacks); isend++ {
		// We deliver each in-flight packet to all stacks, except the one that sent it.
		payload := egr.getPayload(isend)
		if len(payload) == 0 {
			continue
		}
		for irecv := 0; irecv < len(egr.Stacks); irecv++ {
			if irecv == isend {
				continue // Don't deliver to self.
			}
			err = egr.Stacks[irecv].RecvEth(payload)
			if err != nil && !isDroppedPacket(err) {
				t.Errorf("ex[%d] recv[%d]: %s", egr.ex, irecv, err)
			} else if isDroppedPacket(err) && egr.isdebug() {
				t.Logf("ex[%d] recv[%d]: %s", egr.ex, irecv, err)
			}
		}
		egr.zeroPayload(isend)
	}
}

// DoExchanges exchanges packets between stacks until no more data is being sent or maxExchanges is reached.
// By convention client (initiator) is the first stack and server (listener) is the second when dealing with pairs.
func (egr *Exchanger) DoExchanges(t *testing.T, maxExchanges int) (exDone, bytesSent int) {
	t.Helper()
	for ; exDone < maxExchanges; exDone++ {
		pkts, bytes := egr.HandleTx(t)
		bytesSent += bytes
		if pkts == 0 {
			break // No more data being sent.
		}
		egr.HandleRx(t)
	}
	return exDone, bytesSent
}

func isDroppedPacket(err error) bool {
	return err != nil && (errors.Is(err, stacks.ErrDroppedPacket) || strings.HasPrefix(err.Error(), "drop"))
}

func createTCPClientListenerPair(t *testing.T) (client *stacks.TCPConn, listener *stacks.TCPListener) {
	t.Helper()
	const (
		clientPort = 1025
		serverPort = 80
	)
	Stacks := createPortStacks(t, 2)
	clientStack := Stacks[0]
	listenerStack := Stacks[1]

	// Configure listener (server).
	listenerAddr := netip.AddrPortFrom(listenerStack.Addr(), serverPort)
	listener, err := stacks.NewTCPListener(listenerStack, stacks.TCPListenerConfig{
		ConnTxBufSize:  defaultTCPBufferSize,
		MaxConnections: 1,
		ConnRxBufSize:  defaultTCPBufferSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = listener.StartListening(listenerAddr.Port())
	if err != nil {
		t.Fatal(err)
	}
	client = newTCPDialer(t, clientStack, clientPort, listenerAddr, listenerStack.HardwareAddr6())
	return client, listener
}

func createTCPClientServerPair(t *testing.T) (client, server *stacks.TCPConn) {
	t.Helper()
	const (
		clientPort = 1025
		serverPort = 80
	)
	Stacks := createPortStacks(t, 2)
	clientStack := Stacks[0]
	serverStack := Stacks[1]

	// Configure server
	serverIP := netip.AddrPortFrom(serverStack.Addr(), serverPort)

	serverTCP, err := stacks.NewTCPConn(serverStack, stacks.TCPConnConfig{
		TxBufSize: defaultTCPBufferSize,
		RxBufSize: defaultTCPBufferSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = serverTCP.OpenListenTCP(serverIP.Port(), 500)
	if err != nil {
		t.Fatal(err)
	}
	clientTCP := newTCPDialer(t, clientStack, clientPort, serverIP, serverStack.HardwareAddr6())
	return clientTCP, serverTCP
}

func newTCPDialer(t *testing.T, localstack *stacks.PortStack, localPort uint16, remoteAddr netip.AddrPort, remoteMAC [6]byte) *stacks.TCPConn {
	t.Helper()
	// Configure client.
	clientTCP, err := stacks.NewTCPConn(localstack, stacks.TCPConnConfig{
		TxBufSize: defaultTCPBufferSize,
		RxBufSize: defaultTCPBufferSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = clientTCP.OpenDialTCP(localPort, remoteMAC, remoteAddr, 300)
	if err != nil {
		t.Fatal(err)
	}
	return clientTCP
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

func socketReadAllString(s *stacks.TCPConn) string {
	var str strings.Builder
	var buf [256]byte
	for s.BufferedInput() > 0 {
		n, err := s.Read(buf[:])
		str.Write(buf[:n])
		if n == 0 || err != nil {
			break
		}
	}
	return str.String()
}

func socketSendString(s *stacks.TCPConn, str string) {
	_, err := s.Write([]byte(str))
	if err != nil {
		panic(err)
	}
}

func checkNoMoreDataSent(t *testing.T, msg string, egr *Exchanger) {
	t.Helper()
	buf := egr.auxbuf()
	handleTx := func() (txs int) {
		for istack := 0; istack < len(egr.Stacks); istack++ {
			n, _ := egr.Stacks[istack].HandleEth(buf)
			if n > 0 {
				txs++
			}
		}
		return txs
	}

	txs := handleTx()
	if txs > 0 {
		txs2 := handleTx()
		if txs2 > 0 {
			t.Errorf("[txs=%d,%d] unexpected more data: %s; kept sending", txs, txs2, msg)
		} else {
			t.Errorf("[txs=%d] unexpected data: %s", txs, msg)
		}
	}
}

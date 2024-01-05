package stacks_test

import (
	"cmp"
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
	"github.com/soypat/seqs/eth/dns"
	"github.com/soypat/seqs/stacks"
)

var (
	broadcastIPv4 = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	undefinedIPv4 = netip.AddrFrom4([4]byte{})
)

const (
	testingLargeNetworkSize = 2 // Minimum=2
	exchangesToEstablish    = 3
	exchangesToClose        = 3
	defaultMTU              = 2048

	defaultTestDuplexMessages = 128

	finack = seqs.FlagFIN | seqs.FlagACK
	pshack = seqs.FlagPSH | seqs.FlagACK
	synack = seqs.FlagSYN | seqs.FlagACK
)

func TestDNS(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	const questionHost = "www.go.dev"
	siaddr := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	Stacks := createPortStacks(t, networkSize, defaultMTU)

	clientStack := Stacks[0]
	serverStack := Stacks[1]

	clientStack.SetAddr(netip.AddrFrom4([4]byte{}))
	serverStack.SetAddr(netip.AddrFrom4([4]byte{}))

	client := stacks.NewDNSClient(clientStack, dns.ClientPort)
	err := client.StartResolve(stacks.DNSResolveConfig{
		Questions: []dns.Question{
			{Name: dns.MustNewName(questionHost), Type: dns.TypeA, Class: dns.ClassINET},
		},
		DNSAddr:   siaddr,
		DNSHWAddr: serverStack.HardwareAddr6(),
	})
	if err != nil {
		t.Fatal(err)
	}

	egr := NewExchanger(clientStack, serverStack)

	ex, n := egr.HandleTx(t)
	const minDNSSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader + dns.SizeHeader
	if n < minDNSSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDNSSize)
	} else if done, _ := client.IsDone(); done {
		t.Fatal("client done on first exchange?!")
	}
	checkNoMoreDataSent(t, "after client DNS query before server receipt", egr)
}

func TestDHCP(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	siaddr := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	Stacks := createPortStacks(t, networkSize, defaultMTU)

	clientStack := Stacks[0]
	serverStack := Stacks[1]

	clientStack.SetAddr(undefinedIPv4)
	serverStack.SetAddr(undefinedIPv4)

	client := stacks.NewDHCPClient(clientStack, 68)
	server := stacks.NewDHCPServer(serverStack, siaddr, 67)
	testDHCP(t, client, server)
}

func testDHCP(t *testing.T, cl *stacks.DHCPClient, sv *stacks.DHCPServer) {
	var requestedIP = netip.AddrFrom4([4]byte{192, 168, 1, 69})
	cstack := cl.PortStack()
	sstack := sv.PortStack()
	err := cl.BeginRequest(stacks.DHCPRequestConfig{
		RequestedAddr: requestedIP,
		Xid:           0x12345678,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = sv.Start()
	if err != nil {
		t.Fatal(err)
	}
	checkClientNotDone := func(msg string) {
		t.Helper()
		if cl.IsDone() {
			t.Fatalf("client unexpected IsDone=true: %s", msg)
		}
	}
	const minDHCPSize = eth.SizeEthernetHeader + eth.SizeIPv4Header + eth.SizeUDPHeader + eth.SizeDHCPHeader
	// Client performs DISCOVER.
	egr := NewExchanger(cstack, sstack)
	ex, n := egr.HandleTx(t)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	checkNoMoreDataSent(t, "after cl DISCOVER send", egr)
	checkClientNotDone("after DISCOVER send")
	egr.HandleRx(t)

	// Server responds with OFFER.
	ex, n = egr.HandleTx(t)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	checkNoMoreDataSent(t, "after sv OFFER send", egr)
	egr.HandleRx(t) // Client receives OFFER.
	checkClientNotDone("after OFFER recv")

	// Client performs REQUEST.
	ex, n = egr.HandleTx(t)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	checkNoMoreDataSent(t, "after client REQUEST send", egr)
	checkClientNotDone("after REQUEST send")
	egr.HandleRx(t) // Server receives REQUEST.

	// Server performs ACK; client processes ACK
	ex, n = egr.HandleTx(t)
	if n < minDHCPSize {
		t.Errorf("ex[%d] sent=%d want>=%d", ex, n, minDHCPSize)
	}
	checkNoMoreDataSent(t, "after server ACK send", egr)
	egr.HandleRx(t) // Client receives ACK. We are done!
	if !cl.IsDone() {
		t.Fatal("client not processed ACK yet")
	}
}

func TestARP(t *testing.T) {
	const networkSize = testingLargeNetworkSize // How many distinct IP/MAC addresses on network.
	stacks := createPortStacks(t, networkSize, 512)

	sender := stacks[0]
	target := stacks[1]
	if sender.ARP().IsDone() || target.ARP().IsDone() {
		t.Fatal("sender/target is done before any exchange?!")
	}
	testARP(t, sender, target)
	testARP(t, target, sender)
	testARP(t, sender, target)
	sender.ARP().Abort()
	testARP(t, sender, target)
}

func testARP(t *testing.T, sender, target *stacks.PortStack) {
	// Send ARP request from sender to target.
	const expectedARP = eth.SizeEthernetHeader + eth.SizeARPv4Header
	checkSenderNotDone := func(msg string) {
		t.Helper()
		if sender.ARP().IsDone() {
			t.Fatalf("unexpected IsDone=true: %s", msg)
		} else if _, _, err := sender.ARP().ResultAs6(); err == nil {
			t.Fatalf("expected an error on querying result: %s", msg)
		}
	}
	err := sender.ARP().BeginResolve(target.Addr())
	if err != nil {
		t.Fatal(err)
	}
	checkSenderNotDone("right after BeginResolve")

	egr := NewExchanger(sender, target)
	ex, n := egr.HandleTx(t)
	if n != expectedARP {
		t.Errorf("ex[%d] sent=%d want=%d", ex, n, expectedARP)
	}
	checkNoMoreDataSent(t, "after first ARP sent", egr)

	egr.HandleRx(t) // Target receives ARP request.

	// Target responds to sender.
	ex, n = egr.HandleTx(t)
	if n != expectedARP {
		t.Errorf("ex[%d] sent=%d want=%d", ex, n, expectedARP)
	}
	checkNoMoreDataSent(t, "after target ARP response", egr)

	egr.HandleRx(t) // Sender receives ARP response.
	checkNoMoreDataSent(t, "after ARP exchange finish", egr)

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
}

func TestTCPEstablish(t *testing.T) {
	const bufSizes = 32
	client, server := createTCPClientServerPair(t, bufSizes, bufSizes, defaultMTU)
	// 3 way handshake needs 3 exchanges to complete.
	egr := NewExchanger(client.PortStack(), server.PortStack())
	wantStates := makeWantStatesHelper(t, client, server)

	// Test initial states.
	wantStates(seqs.StateSynSent, seqs.StateListen)
	assertOneTCPTx(t, "client initial SYN", seqs.FlagSYN, egr)
	wantStates(seqs.StateSynSent, seqs.StateListen) // Not yet received by server.
	checkNoMoreDataSent(t, "after client SYN", egr)

	egr.HandleRx(t)
	wantStates(seqs.StateSynSent, seqs.StateSynRcvd)
	assertOneTCPTx(t, "server SYN|ACK", synack, egr)
	wantStates(seqs.StateSynSent, seqs.StateSynRcvd)
	checkNoMoreDataSent(t, "after server SYN|ACK", egr)

	// Client established after receiving SYNACK.
	egr.HandleRx(t)
	wantStates(seqs.StateEstablished, seqs.StateSynRcvd)

	// Client responds with ACK.
	assertOneTCPTx(t, "client ACK to server's SYN|ACK", seqs.FlagACK, egr)
	wantStates(seqs.StateEstablished, seqs.StateSynRcvd)
	checkNoMoreDataSent(t, "after client's ACK to SYN|ACK", egr)

	// Server established after receiving ACK to SYNACK.
	egr.HandleRx(t)
	wantStates(seqs.StateEstablished, seqs.StateEstablished)
}

func TestTCPSendReceive_simplex(t *testing.T) {
	const bufSizes = 32
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t, bufSizes, bufSizes, defaultMTU)
	egr := NewExchanger(client.PortStack(), server.PortStack())
	egr.DoExchanges(t, exchangesToEstablish)
	wantStates := makeWantStatesHelper(t, client, server)
	wantStates(seqs.StateEstablished, seqs.StateEstablished)

	// Send data from client to server.
	const data = "hello world"
	socketSendString(client, data)
	egr.DoExchanges(t, 2)
	wantStates(seqs.StateEstablished, seqs.StateEstablished)
	got := socketReadAllString(server)
	if got != data {
		t.Errorf("server: got %q want %q", got, data)
	}
	wantStates(seqs.StateEstablished, seqs.StateEstablished)
}

func TestTCPSendReceive_duplex_single(t *testing.T) {
	const bufSizes = 32
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t, bufSizes, bufSizes, defaultMTU)
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
	client, server := createTCPClientServerPair(t, 32, 32, defaultMTU)
	egr := NewExchanger(client.PortStack(), server.PortStack())
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}

	// Send data from client to server multiple times.
	testSocketDuplex(t, client, server, egr, defaultTestDuplexMessages)
}

func TestTCPClose_noPendingData(t *testing.T) {
	const bufSizes = 32
	// Create Client+Server and establish TCP connection between them.
	client, server := createTCPClientServerPair(t, bufSizes, bufSizes, defaultMTU)
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
	const bufSizes = 512
	client, server := createTCPClientServerPair(t, bufSizes, bufSizes, defaultMTU)
	cstack, sstack := client.PortStack(), server.PortStack()

	egr := NewExchanger(cstack, sstack)
	egr.DoExchanges(t, exchangesToEstablish)
	if client.State() != seqs.StateEstablished || server.State() != seqs.StateEstablished {
		t.Fatalf("not established: client=%s server=%s", client.State(), server.State())
	}
	client.Close()
	egr.DoExchanges(t, exchangesToClose)
	if !client.State().IsClosed() || !server.State().IsClosed() {
		t.Fatalf("not closed: client=%s server=%s", client.State(), server.State())
	}
	// TODO(soypat): We need an extra exchange to close the connection since client is left in TimeWait and still not aborted.
	// How to simplify this?
	egr.HandleTx(t)

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
	testSocketDuplex(t, client, server, egr, defaultTestDuplexMessages)
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
	txs, _ := egr.HandleTx(t)
	if txs != 2 {
		t.Errorf("expected 2 ACK segments exchanged on duplex end, got %d", txs)
	} else {
		s1, s2 := egr.SegmentToLast(0), egr.SegmentToLast(1)
		if s1.Flags != seqs.FlagACK || s2.Flags != seqs.FlagACK {
			t.Errorf("expected ACK segments exchanged on duplex end, got %v,%v", s1.Flags, s2.Flags)
		}
	}
	checkNoMoreDataSent(t, "after duplex ACKs", egr)
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
			MTU:             defaultMTU,
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
	const bufSizes = 2048
	client, listener := createTCPClientListenerPair(t, bufSizes, bufSizes, 1)
	egr := NewExchanger(client.PortStack(), listener.PortStack())
	// Establish the connection on one port.
	exdone, _ := egr.DoExchanges(t, exchangesToEstablish)
	if exdone == 0 {
		panic(exdone)
	}
	netconn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	server := netconn.(*stacks.TCPConn)
	wantStates := makeWantStatesHelper(t, client, server)

	wantStates(seqs.StateEstablished, seqs.StateEstablished)
	testSocketDuplex(t, client, server, egr, defaultTestDuplexMessages)

	// Close socket to trigger closing FIN sequence.
	client.Close()
	wantStates(seqs.StateFinWait1, seqs.StateEstablished)

	assertOneTCPTx(t, "client close; sends FIN|ACK", finack, egr)
	wantStates(seqs.StateFinWait1, seqs.StateEstablished)
	egr.HandleRx(t)
	wantStates(seqs.StateFinWait1, seqs.StateCloseWait)

	assertOneTCPTx(t, "server ACK of FIN|ACK", seqs.FlagACK, egr)
	wantStates(seqs.StateFinWait1, seqs.StateCloseWait)
	egr.HandleRx(t)
	wantStates(seqs.StateFinWait2, seqs.StateCloseWait)

	// TODO(soypat): fix this part of the close test!
	return
	assertOneTCPTx(t, "server ACK of FIN|ACK", seqs.FlagACK, egr)
	wantStates(seqs.StateFinWait1, seqs.StateCloseWait)

	if !client.State().IsClosed() || !server.State().IsClosed() {
		t.Fatalf("not closed: client=%s server=%s", client.State(), server.State())
	}
}

type Exchanger struct {
	Stacks   []*stacks.PortStack
	pipesN   []int
	pipes    [][]byte
	segments []seqs.Segment
	ex       int
	loglevel slog.Level
}

func NewExchanger(stacks ...*stacks.PortStack) *Exchanger {
	egr := &Exchanger{
		Stacks: stacks,
		pipesN: make([]int, len(stacks)),
		pipes:  make([][]byte, len(stacks)),
		ex:     -1,
	}
	n := 0
	for i := range stacks {
		n += int(stacks[i].MTU())
	}
	buf := make([]byte, n)
	n = 0
	for i := range stacks {
		end := n + int(stacks[i].MTU())
		egr.pipes[i] = buf[n:end]
		n = end
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
}

// auxbuf returns an unused buffer for temporary use. Do not hold references to this buffer during calls to HandleTx.
func (egr *Exchanger) auxbuf() []byte {
	for istack := 0; istack < len(egr.Stacks); istack++ {
		if egr.pipesN[istack] == 0 {
			return egr.pipes[istack][:]
		}
	}
	return make([]byte, defaultMTU)
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

func createTCPClientListenerPair(t *testing.T, clientSizes, listenerSizes, maxListenerConns uint16) (client *stacks.TCPConn, listener *stacks.TCPListener) {
	t.Helper()
	const (
		clientPort = 1025
		serverPort = 80
	)
	Stacks := createPortStacks(t, 2, defaultMTU)
	clientStack := Stacks[0]
	listenerStack := Stacks[1]

	// Configure listener (server).
	listenerAddr := netip.AddrPortFrom(listenerStack.Addr(), serverPort)
	listener, err := stacks.NewTCPListener(listenerStack, stacks.TCPListenerConfig{
		ConnTxBufSize:  listenerSizes,
		MaxConnections: maxListenerConns,
		ConnRxBufSize:  listenerSizes,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = listener.StartListening(listenerAddr.Port())
	if err != nil {
		t.Fatal(err)
	}
	client = newTCPDialer(t, clientStack, clientPort, clientSizes, listenerAddr, listenerStack.HardwareAddr6())
	return client, listener
}

func createTCPClientServerPair(t *testing.T, clientSizes, serverSizes, mtu uint16) (client, server *stacks.TCPConn) {
	t.Helper()
	const (
		clientPort = 1025
		serverPort = 80
	)
	Stacks := createPortStacks(t, 2, mtu)
	clientStack := Stacks[0]
	serverStack := Stacks[1]

	// Configure server
	serverIP := netip.AddrPortFrom(serverStack.Addr(), serverPort)

	serverTCP, err := stacks.NewTCPConn(serverStack, stacks.TCPConnConfig{
		TxBufSize: serverSizes,
		RxBufSize: serverSizes,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = serverTCP.OpenListenTCP(serverIP.Port(), 500)
	if err != nil {
		t.Fatal(err)
	}
	clientTCP := newTCPDialer(t, clientStack, clientPort, clientSizes, serverIP, serverStack.HardwareAddr6())
	return clientTCP, serverTCP
}

func newTCPDialer(t *testing.T, localstack *stacks.PortStack, localPort, bufSizes uint16, remoteAddr netip.AddrPort, remoteMAC [6]byte) *stacks.TCPConn {
	t.Helper()
	// Configure client.
	clientTCP, err := stacks.NewTCPConn(localstack, stacks.TCPConnConfig{
		TxBufSize: bufSizes,
		RxBufSize: bufSizes,
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

func createPortStacks(t *testing.T, n int, mtu uint16) (Stacks []*stacks.PortStack) {
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
			MTU:             mtu,
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
		retriesBeforeInfLoop := 1000
		for handleTx() > 0 {
			retriesBeforeInfLoop--
			if retriesBeforeInfLoop == 0 {
				t.Fatal("likely infinite send loop detected")
			}
		}
		t.Errorf("[txs=%d] unexpected data: %s", txs, msg)
	}
}
func assertOneTCPTx(t *testing.T, msg string, wantFlags seqs.Flags, egr *Exchanger) {
	t.Helper()
	nseg := len(egr.segments)
	txs, n := egr.HandleTx(t)
	totsegs := len(egr.segments) - nseg
	if txs == 0 {
		t.Fatalf("no data sent: %s", msg)
	} else if n < 54 {
		t.Fatalf("wanted one TCP packet, got short %d", n)
	} else if txs > 1 {
		t.Fatalf("more than one tx: %d", txs)
	} else if totsegs != 1 {
		t.Fatal("expected one TCP segment")
	} else if egr.LastSegment().Flags != wantFlags {
		t.Fatalf("expected flags=%v got=%v", wantFlags, egr.LastSegment().Flags)
	}
}

func makeWantStatesHelper(t *testing.T, client, server *stacks.TCPConn) func(cs, ss seqs.State) {
	return func(cs, ss seqs.State) {
		t.Helper()
		gotcs := client.State()
		gotss := server.State()
		if cs == seqs.StateEstablished && ss == seqs.StateEstablished &&
			(gotcs != seqs.StateEstablished || gotss != seqs.StateEstablished) {
			// Expecting established connection special case.
			t.Errorf("not established client=%s server=%s", gotcs, gotss)
			return
		}
		if gotcs != cs {
			t.Errorf("client state got=%s want=%s", client.State(), cs)
		}
		if gotss != ss {
			t.Errorf("server state got=%s want=%s", server.State(), ss)
		}
	}
}

func max[T cmp.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

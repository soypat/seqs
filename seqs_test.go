package seqs_test

import (
	"strconv"
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
)

const (
	SYNACK = seqs.FlagSYN | seqs.FlagACK
	FINACK = seqs.FlagFIN | seqs.FlagACK
	PSHACK = seqs.FlagPSH | seqs.FlagACK
)

/*
	 Section 3.5 of RFC 9293: Basic 3-way handshake for connection synchronization.
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

		5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED
*/
func TestExchange_rfc9293_figure6(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []seqs.Exchange{
		{ // A sends SYN to B.
			Outgoing:  &seqs.Segment{SEQ: issA, Flags: seqs.FlagSYN, WND: windowA},
			WantState: seqs.StateSynSent,
		},
		{ // A receives SYNACK from B thus establishing the connection on A's side.
			Incoming:    &seqs.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState:   seqs.StateEstablished,
			WantPending: &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
		},
		{ // A sends ACK to B, which leaves connection established on their side. Three way handshake complete by now.
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
	}
	var tcbA seqs.ControlBlock
	tcbA.HelperInitState(seqs.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)
	segA, ok := tcbA.PendingSegment(0)
	if ok {
		t.Error("unexpected Client pending segment after establishment: ", segA)
	}
	exchangeB := reverseExchange(exchangeA, seqs.StateSynRcvd, seqs.StateSynRcvd, seqs.StateEstablished)

	var tcbB seqs.ControlBlock
	tcbB.HelperInitState(seqs.StateListen, issB, issB, windowB)
	tcbB.HelperExchange(t, exchangeB) // TODO remove [:3] after snd.UNA bugfix
	segB, ok := tcbB.PendingSegment(0)
	if ok {
		t.Error("unexpected Listener pending segment after establishment: ", segB)
	}
}

/*
	 Section 3.5 of RFC 9293: Simultaneous Connection Synchronization (SYN).
		TCP Peer A                                       TCP Peer B

		1.  CLOSED                                           CLOSED

		2.  SYN-SENT     --> <SEQ=100><CTL=SYN>              ...

		3.  SYN-RECEIVED <-- <SEQ=300><CTL=SYN>              <-- SYN-SENT

		4.               ... <SEQ=100><CTL=SYN>              --> SYN-RECEIVED

		5.  SYN-RECEIVED --> <SEQ=100><ACK=301><CTL=SYN,ACK> ...

		6.  ESTABLISHED  <-- <SEQ=300><ACK=101><CTL=SYN,ACK> <-- SYN-RECEIVED

		7.               ... <SEQ=100><ACK=301><CTL=SYN,ACK> --> ESTABLISHED
*/
func TestExchange_rfc9293_figure7(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []seqs.Exchange{
		0: { // A sends SYN to B.
			Outgoing:  &seqs.Segment{SEQ: issA, Flags: seqs.FlagSYN, WND: windowA},
			WantState: seqs.StateSynSent,
		},
		1: { // A receives a SYN with no ACK from B.
			Incoming:    &seqs.Segment{SEQ: issB, Flags: seqs.FlagSYN, WND: windowB},
			WantState:   seqs.StateSynRcvd,
			WantPending: &seqs.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
		},
		2: { // A sends SYNACK to B.
			Outgoing:  &seqs.Segment{SEQ: issA, ACK: issB + 1, Flags: SYNACK, WND: windowA},
			WantState: seqs.StateSynRcvd,
		},
		3: { // A receives ACK from B.
			Incoming:  &seqs.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
	}
	var tcbA seqs.ControlBlock
	tcbA.HelperInitState(seqs.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)
}

/*
	 Recovery from Old Duplicate SYN
		TCP Peer A                                           TCP Peer B

		1.  CLOSED                                               LISTEN

		2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               ...

		3.  (duplicate) ... <SEQ=90><CTL=SYN>               --> SYN-RECEIVED

		4.  SYN-SENT    <-- <SEQ=300><ACK=91><CTL=SYN,ACK>  <-- SYN-RECEIVED

		5.  SYN-SENT    --> <SEQ=91><CTL=RST>               --> LISTEN

		6.              ... <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

		7.  ESTABLISHED <-- <SEQ=400><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

		8.  ESTABLISHED --> <SEQ=101><ACK=401><CTL=ACK>      --> ESTABLISHED
*/
func TestExchange_rfc9293_figure8(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	const issAold = 90
	const issBNew = issB + seqs.RSTJump
	exchangeA := []seqs.Exchange{
		0: { // A sends new SYN to B (which is not received).
			Outgoing:  &seqs.Segment{SEQ: issA, Flags: seqs.FlagSYN, WND: windowA},
			WantState: seqs.StateSynSent,
		},
		1: { // Receive SYN from B acking an old "duplicate" SYN.
			Incoming:    &seqs.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
			WantState:   seqs.StateSynSent,
			WantPending: &seqs.Segment{SEQ: issAold + 1, Flags: seqs.FlagRST, WND: windowA},
		},
		2: { // A sends RST to B and makes segment believable by using the old SEQ.
			Outgoing:  &seqs.Segment{SEQ: issAold + 1, Flags: seqs.FlagRST, WND: windowA},
			WantState: seqs.StateSynSent,
		},
		3: { // A sends a duplicate SYN to B.
			Outgoing:  &seqs.Segment{SEQ: issA, Flags: seqs.FlagSYN, WND: windowA},
			WantState: seqs.StateSynSent,
		},
		4: { // B SYNACKs new SYN.
			Incoming:    &seqs.Segment{SEQ: issBNew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState:   seqs.StateEstablished,
			WantPending: &seqs.Segment{SEQ: issA + 1, ACK: issBNew + 1, Flags: seqs.FlagACK, WND: windowA},
		},
		5: { // B receives ACK from A.
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issBNew + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
	}
	var tcbA seqs.ControlBlock
	tcbA.HelperInitState(seqs.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)

	exchangeB := []seqs.Exchange{
		0: { // B receives old SYN from A.
			Incoming:    &seqs.Segment{SEQ: issAold, Flags: seqs.FlagSYN, WND: windowA},
			WantState:   seqs.StateSynRcvd,
			WantPending: &seqs.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
		},
		1: { // B SYNACKs old SYN.
			Outgoing:  &seqs.Segment{SEQ: issB, ACK: issAold + 1, Flags: SYNACK, WND: windowB},
			WantState: seqs.StateSynRcvd,
		},
		2: { // B receives RST from A.
			Incoming:  &seqs.Segment{SEQ: issAold + 1, Flags: seqs.FlagRST, WND: windowA},
			WantState: seqs.StateListen,
		},
		3: { // B receives new SYN from A.
			Incoming:    &seqs.Segment{SEQ: issA, Flags: seqs.FlagSYN, WND: windowA},
			WantState:   seqs.StateSynRcvd,
			WantPending: &seqs.Segment{SEQ: issBNew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
		},
		4: { // B SYNACKs new SYN.
			Outgoing:  &seqs.Segment{SEQ: issBNew, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState: seqs.StateSynRcvd,
		},
		5: { // B receives ACK from A.
			Incoming:  &seqs.Segment{SEQ: issA + 1, ACK: issBNew + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
	}
	var tcbB seqs.ControlBlock
	tcbB.HelperInitState(seqs.StateListen, issB, issB, windowB)
	tcbB.HelperExchange(t, exchangeB)
}

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
func TestExchange_rfc9293_figure12(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []seqs.Exchange{
		0: { // A sends FIN|ACK to B to begin closing connection.
			Outgoing:  &seqs.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
			WantState: seqs.StateFinWait1,
		},
		1: { // A receives ACK from B.
			Incoming:  &seqs.Segment{SEQ: issB, ACK: issA + 1, Flags: seqs.FlagACK, WND: windowB},
			WantState: seqs.StateFinWait2,
		},
		2: { // A receives FIN|ACK from B.
			Incoming:    &seqs.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB},
			WantState:   seqs.StateTimeWait,
			WantPending: &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
		},
		3: { // A sends ACK to B.
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateTimeWait, // Technically we should be in TimeWait here.
		},
	}
	var tcbA seqs.ControlBlock
	tcbA.HelperInitState(seqs.StateEstablished, issA, issA, windowA)
	tcbA.HelperInitRcv(issB, issB, windowB)
	tcbA.HelperExchange(t, exchangeA)

	exchangeB := reverseExchange(exchangeA, seqs.StateCloseWait, seqs.StateCloseWait, seqs.StateLastAck, seqs.StateClosed)
	exchangeB[1].WantPending = &seqs.Segment{SEQ: issB, ACK: issA + 1, Flags: FINACK, WND: windowB}
	var tcbB seqs.ControlBlock
	tcbB.HelperInitState(seqs.StateEstablished, issB, issB, windowB)
	tcbB.HelperInitRcv(issA, issA, windowA)
	tcbB.HelperExchange(t, exchangeB)
}

/*
	 Figure 12: Simultaneous Close Sequence
			TCP Peer A                                           TCP Peer B

		1.  ESTABLISHED                                          ESTABLISHED

		2.  (Close)                                              (Close)
			FIN-WAIT-1  --> <SEQ=100><ACK=300><CTL=FIN,ACK>  ... FIN-WAIT-1
						<-- <SEQ=300><ACK=100><CTL=FIN,ACK>  <--
						... <SEQ=100><ACK=300><CTL=FIN,ACK>  -->

		3.  CLOSING     --> <SEQ=101><ACK=301><CTL=ACK>      ... CLOSING
						<-- <SEQ=301><ACK=101><CTL=ACK>      <--
						... <SEQ=101><ACK=301><CTL=ACK>      -->

		4.  TIME-WAIT                                            TIME-WAIT
			(2 MSL)                                              (2 MSL)
			CLOSED                                               CLOSED
*/
func TestExchange_rfc9293_figure13(t *testing.T) {
	const issA, issB, windowA, windowB = 100, 300, 1000, 1000
	exchangeA := []seqs.Exchange{
		0: { // A sends FIN|ACK to B to begin closing connection.
			Outgoing:  &seqs.Segment{SEQ: issA, ACK: issB, Flags: FINACK, WND: windowA},
			WantState: seqs.StateFinWait1,
		},
		1: { // A receives FIN|ACK from B, who sent packet before receiving A's FINACK.
			Incoming:    &seqs.Segment{SEQ: issB, ACK: issA, Flags: FINACK, WND: windowB},
			WantState:   seqs.StateClosing,
			WantPending: &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
		},
		2: { // A sends ACK to B.
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateTimeWait,
		},
	}
	var tcbA seqs.ControlBlock
	tcbA.HelperInitState(seqs.StateEstablished, issA, issA, windowA)
	tcbA.HelperInitRcv(issB, issB, windowB)
	tcbA.HelperExchange(t, exchangeA)

	// No need to test B since exchange is completely symmetric.
}

// This test reenacts a full client-server interaction in the sending and receiving
// of the 12 byte message "hello world\n" over TCP.
func TestExchange_helloworld(t *testing.T) {
	// Client Transmission Control Block.
	var tcbA seqs.ControlBlock
	defer tcbA.HelperPrintDebugInfoOnFail(t)
	const windowA, windowB = 502, 4096
	const issA, issB = 0x5e722b7d, 0xbe6e4c0f
	const datalen = 12
	exchangeA := []seqs.Exchange{
		0: { // A sends SYN to B.
			Outgoing:  &seqs.Segment{SEQ: issA, Flags: seqs.FlagSYN, WND: windowA},
			WantState: seqs.StateSynSent,
		},
		1: { // A receives SYNACK from B.
			Incoming:    &seqs.Segment{SEQ: issB, ACK: issA + 1, Flags: SYNACK, WND: windowB},
			WantState:   seqs.StateEstablished,
			WantPending: &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
		},
		2: { // A sends ACK to B thus establishing connection.
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
		3: { // A sends PSH|ACK to B with 12 byte message: "hello world\n"
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: PSHACK, WND: windowA, DATALEN: datalen},
			WantState: seqs.StateEstablished,
		},
		4: { // A receives ACK from B of last message.
			Incoming:  &seqs.Segment{SEQ: issB + 1, ACK: issA + 1 + datalen, Flags: seqs.FlagACK, WND: windowB},
			WantState: seqs.StateEstablished,
		},
		5: { // A receives PSH|ACK from B with echoed 12 byte message: "hello world\n"
			Incoming:    &seqs.Segment{SEQ: issB + 1, ACK: issA + 1 + datalen, Flags: PSHACK, WND: windowB, DATALEN: datalen},
			WantState:   seqs.StateEstablished,
			WantPending: &seqs.Segment{SEQ: issA + 1 + datalen, ACK: issB + 1 + datalen, Flags: seqs.FlagACK, WND: windowA},
		},
		6: { // A ACKs B's message.
			Outgoing:  &seqs.Segment{SEQ: issA + 1 + datalen, ACK: issB + 1 + datalen, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
		7: { // A sends PSH|ACK to B with SECOND 12 byte message.
			Outgoing:  &seqs.Segment{SEQ: issA + 1 + datalen, ACK: issB + 1 + datalen, Flags: PSHACK, WND: windowA, DATALEN: datalen},
			WantState: seqs.StateEstablished,
		},
		8: { // A receives PSH|ACK that acks last message and contains echoed of SECOND 12 byte message.
			Incoming:    &seqs.Segment{SEQ: issB + 1 + datalen, ACK: issA + 1 + 2*datalen, Flags: PSHACK, WND: windowB, DATALEN: datalen},
			WantState:   seqs.StateEstablished,
			WantPending: &seqs.Segment{SEQ: issA + 1 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: seqs.FlagACK, WND: windowA},
		},
		9: { // A ACKs B's SECOND message.
			Outgoing:  &seqs.Segment{SEQ: issA + 1 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
		10: { // A sends FIN|ACK to B to close connection.
			Outgoing:  &seqs.Segment{SEQ: issA + 1 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: FINACK, WND: windowA},
			WantState: seqs.StateFinWait1,
		},
		11: { // A receives B's ACK of FIN.
			Incoming:    &seqs.Segment{SEQ: issB + 1 + 2*datalen, ACK: issA + 2 + 2*datalen, Flags: seqs.FlagACK, WND: windowB},
			WantState:   seqs.StateFinWait2,
			WantPending: &seqs.Segment{SEQ: issA + 2 + 2*datalen, ACK: issB + 1 + 2*datalen, Flags: seqs.FlagACK, WND: windowA},
		},
	}
	// The client starts in the SYN_SENT state with a random sequence number.
	gotServerSeg, _ := parseSegment(t, exchangeHelloWorld[0])
	tcbA.HelperInitState(seqs.StateSynSent, gotServerSeg.SEQ, gotServerSeg.SEQ, windowB)
	tcbA.HelperExchange(t, exchangeA)

	exchangeB := reverseExchange(exchangeA, seqs.StateSynRcvd, seqs.StateSynRcvd,
		seqs.StateEstablished, seqs.StateEstablished, seqs.StateEstablished, seqs.StateEstablished,
		seqs.StateEstablished, seqs.StateEstablished, seqs.StateEstablished, seqs.StateEstablished,
		seqs.StateCloseWait, seqs.StateCloseWait)

	exchangeB[7].WantPending = nil // Is an unpredicable action.
	var tcbB seqs.ControlBlock
	defer tcbB.HelperPrintDebugInfoOnFail(t)

	tcbB.HelperInitState(seqs.StateListen, issB, issB, windowB)
	tcbB.HelperInitRcv(issA, issA, windowA)
	tcbB.HelperExchange(t, exchangeB)
}

func TestExchange_helloworld_client(t *testing.T) {
	// Client Transmission Control Block.
	var tcb seqs.ControlBlock
	defer tcb.HelperPrintDebugInfoOnFail(t)
	// The client starts in the SYN_SENT state with a random sequence number.
	gotClientSeg, _ := parseSegment(t, exchangeHelloWorld[0])

	// We add the SYN state to the client.
	tcb.HelperInitState(seqs.StateSynSent, gotClientSeg.SEQ, gotClientSeg.SEQ, gotClientSeg.WND)
	err := tcb.Send(gotClientSeg)
	if err != nil {
		t.Fatal(err)
	}
	tcb.HelperPrintSegment(t, false, gotClientSeg)

	segString := func(seg seqs.Segment) string {
		return tcb.RelativeAutoSegment(seg).RelativeGoString(0, 0)
	}
	for i, packet := range exchangeHelloWorld {
		if i == 0 {
			continue // we already processed first packet.
		}
		seg, payload := parseSegment(t, packet)
		if seg.DATALEN > 0 {
			t.Logf("seg[%d] <%s> payload: %q", i, tcb.State(), string(payload))
		} else {
			t.Logf("seg[%d] <%s>", i, tcb.State())
		}
		isClient := packet[0] == 0x28
		if isClient {
			isPSH := seg.Flags&seqs.FlagPSH != 0
			gotClientSeg.Flags |= seg.Flags & (seqs.FlagPSH | seqs.FlagFIN) // Can't predict when client will send FIN.
			if isPSH {
				gotClientSeg.DATALEN = seg.DATALEN
			}

			gotClientSeg.WND = seg.WND // Ignore window field, not a core part of control flow.
			if gotClientSeg != seg {
				t.Fatalf("client:\n got=%+v\nwant=%+v", segString(gotClientSeg), segString(seg))
			}
			err := tcb.Send(gotClientSeg)
			if err != nil {
				t.Fatalf("incoming %s:\nseg[%d]=%s\nrcv=%+v\nsnd=%+v", err, i, segString(gotClientSeg), tcb.RelativeRecvSpace(), tcb.RelativeSendSpace())
			}
			tcb.HelperPrintSegment(t, false, gotClientSeg)
			continue // we only pass server packets to the client.
		}
		err = tcb.Recv(seg)
		if err != nil {
			t.Fatalf("%s:\nseg[%d]=%s\nrcv=%+v\nsnd=%+v", err, i, segString(seg), tcb.RelativeRecvSpace(), tcb.RelativeSendSpace())
		}
		tcb.HelperPrintSegment(t, true, seg)
		var ok bool
		gotClientSeg, ok = tcb.PendingSegment(0)
		if !ok {
			t.Fatalf("[%d]: got no segment state=%s", i, tcb.State())
		}
	}
}

func parseSegment(t *testing.T, b []byte) (seqs.Segment, []byte) {
	t.Helper()
	ehdr := eth.DecodeEthernetHeader(b)
	if ehdr.AssertType() != eth.EtherTypeIPv4 {
		t.Fatalf("not IPv4")
	}
	ip, ipOffset := eth.DecodeIPv4Header(b[eth.SizeEthernetHeader:])
	if ip.Protocol != 6 {
		t.Fatalf("not TCP")
	}
	tcp, tcpOffset := eth.DecodeTCPHeader(b[eth.SizeEthernetHeader+ipOffset:])
	offset := eth.SizeEthernetHeader + ipOffset + tcpOffset
	end := ip.TotalLength + eth.SizeEthernetHeader
	if int(end) > len(b) {
		t.Fatalf("bad ip.TotalLength")
	}
	payload := b[offset:end]
	return tcp.Segment(len(payload)), payload
}

func reverseExchange(exchange []seqs.Exchange, states ...seqs.State) []seqs.Exchange {
	if len(exchange) != len(states) || len(exchange) == 0 {
		panic("len(exchange) != len(states) or empty exchange: " + strconv.Itoa(len(exchange)) + " " + strconv.Itoa(len(states)))
	}
	firstIsIn := exchange[0].Incoming != nil
	if firstIsIn {
		panic("please start with an outgoing segment to reverse exchange for best test results")
	}
	out := make([]seqs.Exchange, len(exchange))
	for i := range exchange {
		isLast := i == len(exchange)-1
		isOut := exchange[i].Outgoing != nil

		out[i].WantState = states[i]
		if isOut {
			out[i].Incoming = exchange[i].Outgoing
			if !isLast {
				out[i].WantPending = exchange[i+1].Incoming
			}
		} else {
			out[i].Outgoing = exchange[i].Incoming
		}
	}
	return out
}

// Full client-server interaction in the sending of "hello world" over TCP in order.
var exchangeHelloWorld = [][]byte{
	// client SYN1
	0: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x3c\x71\xac\x40\x00\x40\x06\x44\x9b\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7d\x00\x00\x00\x00\xa0\x02\xfa\xf0\x27\x6d\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a\x07\x8b\x86\x4a\x00\x00\x00\x00\x01\x03\x03\x07"),
	// server SYNACK
	1: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x0f\x5e\x72\x2b\x7e\x80\x12\x10\x00\xc0\xbb\x00\x00\x02\x04\x05\xb4\x03\x03\x00\x04\x02\x00\x00\x00"),
	// client ACK1
	2: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xad\x40\x00\x40\x06\x44\xae\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7e\xbe\x6e\x4c\x10\x50\x10\x01\xf6\x0b\x92\x00\x00"),
	// client PSHACK0
	3: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x34\x71\xae\x40\x00\x40\x06\x44\xa1\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7e\xbe\x6e\x4c\x10\x50\x18\x01\xf6\x79\xa5\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// server ACK1
	4: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\xb6\x5b\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x10\x5e\x72\x2b\x8a\x50\x10\x0f\xf4\xfd\x87\x00\x00\x00\x00\x00\x00\x00\x00"),
	// server PSHACK1
	5: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x10\x5e\x72\x2b\x8a\x50\x18\x10\x00\x6b\x8f\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// client ACK2
	6: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xaf\x40\x00\x40\x06\x44\xac\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x8a\xbe\x6e\x4c\x1c\x50\x10\x01\xf6\x0b\x7a\x00\x00"),
	// client PSHACK1
	7: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x34\x71\xb0\x40\x00\x40\x06\x44\x9f\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x8a\xbe\x6e\x4c\x1c\x50\x18\x01\xf6\x79\x8d\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// server PSHACK2
	8: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x1c\x5e\x72\x2b\x96\x50\x18\x10\x00\x6b\x77\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// client ACK3
	9: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xb1\x40\x00\x40\x06\x44\xaa\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x96\xbe\x6e\x4c\x28\x50\x10\x01\xf6\x0b\x62\x00\x00"),
	// client FINACK
	10: []byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xb2\x40\x00\x40\x06\x44\xa9\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x96\xbe\x6e\x4c\x28\x50\x11\x01\xf6\x0b\x61\x00\x00"),
	// server ACK
	11: []byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\xb6\x5b\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x28\x5e\x72\x2b\x97\x50\x10\x10\x00\xfd\x56\x00\x00\x00\x00\x00\x00\x00\x00"),
}

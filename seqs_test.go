package seqs_test

import (
	"testing"

	"github.com/soypat/seqs"
	"github.com/soypat/seqs/eth"
)

const (
	SYNACK = seqs.FlagSYN | seqs.FlagACK
	FINACK = seqs.FlagFIN | seqs.FlagACK
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
		{ // A sends data to B?
			Outgoing:  &seqs.Segment{SEQ: issA + 1, ACK: issB + 1, Flags: seqs.FlagACK, WND: windowA},
			WantState: seqs.StateEstablished,
		},
	}
	var tcbA seqs.ControlBlock
	tcbA.HelperInitState(seqs.StateSynSent, issA, issA, windowA)
	tcbA.HelperExchange(t, exchangeA)
	exchangeB := reverseExchange(exchangeA, seqs.StateSynRcvd, seqs.StateSynRcvd, seqs.StateEstablished, seqs.StateEstablished)

	var tcbB seqs.ControlBlock
	tcbB.HelperInitState(seqs.StateListen, issB, issB, windowB)
	tcbB.HelperExchange(t, exchangeB) // TODO remove [:3] after snd.UNA bugfix
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
}

func TestExchange_helloworld_client(t *testing.T) {
	// Client Transmission Control Block.
	var tcb seqs.ControlBlock
	// The client starts in the SYN_SENT state with a random sequence number.
	gotClientSeg := parseSegment(t, exchangeHelloWorld[0])

	// We add the SYN state to the client.
	tcb.HelperInitState(seqs.StateSynSent, gotClientSeg.SEQ, gotClientSeg.SEQ, gotClientSeg.WND)
	err := tcb.Send(gotClientSeg)
	if err != nil {
		t.Fatal(err)
	}
	tcb.HelperPrintSegment(t, false, gotClientSeg)
	packets := exchangeHelloWorld[1:]

	for i, packet := range packets {
		_ = i
		seg := parseSegment(t, packet)
		isClient := packet[0] == 0x28
		if isClient {
			isPSH := seg.Flags&seqs.FlagPSH != 0
			if isPSH {
				gotClientSeg.Flags |= seqs.FlagPSH
				gotClientSeg.DATALEN = seg.DATALEN
			}

			gotClientSeg.WND = seg.WND // Ignore window field, not a core part of control flow.
			if gotClientSeg != seg {
				t.Errorf("client: got %+v, want %+v", gotClientSeg, seg)
			}
			err := tcb.Send(gotClientSeg)
			if err != nil {
				t.Fatalf("%s\noutgoing seg=%s", err, tcb.RelativeAutoSegment(gotClientSeg).RelativeGoString(0, 0))
			}
			tcb.HelperPrintSegment(t, false, gotClientSeg)
			continue // we only pass server packets to the client.
		}
		err = tcb.Recv(seg)
		if err != nil {
			t.Fatalf("%s\nincoming seg%d=%s", err, i, tcb.RelativeAutoSegment(seg).RelativeGoString(0, 0))
		}
		tcb.HelperPrintSegment(t, true, seg)
		var ok bool
		gotClientSeg, ok = tcb.PendingSegment(0)
		if !ok {
			t.Fatalf("client%d: got no segment state=%s", i, tcb.State())
		}
	}
}

func parseSegment(t *testing.T, b []byte) seqs.Segment {
	t.Helper()
	ehdr := eth.DecodeEthernetHeader(b)
	if ehdr.AssertType() != eth.EtherTypeIPv4 {
		t.Fatalf("not IPv4")
	}
	ip := eth.DecodeIPv4Header(b[eth.SizeEthernetHeader:])
	if ip.Protocol != 6 {
		t.Fatalf("not TCP")
	}
	tcp := eth.DecodeTCPHeader(b[eth.SizeEthernetHeader+ip.IHL()*4:])
	offset := eth.SizeEthernetHeader + ip.IHL()*4 + tcp.OffsetInBytes()
	if ip.TotalLength > uint16(len(b)-eth.SizeEthernetHeader) {
		t.Fatalf("bad ip length")
	}
	payload := b[offset:]
	return seqs.Segment{
		SEQ:     tcp.Seq,
		ACK:     tcp.Ack,
		WND:     tcp.WindowSize(),
		DATALEN: seqs.Size(len(payload)),
		Flags:   tcp.Flags(),
	}
}

func reverseExchange(exchange []seqs.Exchange, states ...seqs.State) []seqs.Exchange {
	if len(exchange) != len(states) || len(exchange) == 0 {
		panic("len(exchange) != len(states) or empty exchange")
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
	// cSYN1
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x3c\x71\xac\x40\x00\x40\x06\x44\x9b\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7d\x00\x00\x00\x00\xa0\x02\xfa\xf0\x27\x6d\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a\x07\x8b\x86\x4a\x00\x00\x00\x00\x01\x03\x03\x07"),
	// sSYNACK
	[]byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x0f\x5e\x72\x2b\x7e\x80\x12\x10\x00\xc0\xbb\x00\x00\x02\x04\x05\xb4\x03\x03\x00\x04\x02\x00\x00\x00"),
	// cACK1
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xad\x40\x00\x40\x06\x44\xae\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7e\xbe\x6e\x4c\x10\x50\x10\x01\xf6\x0b\x92\x00\x00"),
	// cPSHACK0
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x34\x71\xae\x40\x00\x40\x06\x44\xa1\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x7e\xbe\x6e\x4c\x10\x50\x18\x01\xf6\x79\xa5\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// sACK1
	[]byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\xb6\x5b\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x10\x5e\x72\x2b\x8a\x50\x10\x0f\xf4\xfd\x87\x00\x00\x00\x00\x00\x00\x00\x00"),
	// sPSHACK1
	[]byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x10\x5e\x72\x2b\x8a\x50\x18\x10\x00\x6b\x8f\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// cACK2
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xaf\x40\x00\x40\x06\x44\xac\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x8a\xbe\x6e\x4c\x1c\x50\x10\x01\xf6\x0b\x7a\x00\x00"),
	// cPSHACK1
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x34\x71\xb0\x40\x00\x40\x06\x44\x9f\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x8a\xbe\x6e\x4c\x1c\x50\x18\x01\xf6\x79\x8d\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// sPSHACK2
	[]byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x34\x00\x00\x40\x00\x40\x06\xb6\x4f\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x1c\x5e\x72\x2b\x96\x50\x18\x10\x00\x6b\x77\x00\x00\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x0a"),
	// cACK3
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xb1\x40\x00\x40\x06\x44\xaa\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x96\xbe\x6e\x4c\x28\x50\x10\x01\xf6\x0b\x62\x00\x00"),
	// cFINACK
	[]byte("\x28\xcd\xc1\x05\x4d\xbb\xd8\x5e\xd3\x43\x03\xeb\x08\x00\x45\x00\x00\x28\x71\xb2\x40\x00\x40\x06\x44\xa9\xc0\xa8\x01\x93\xc0\xa8\x01\x91\x84\x96\x04\xd2\x5e\x72\x2b\x96\xbe\x6e\x4c\x28\x50\x11\x01\xf6\x0b\x61\x00\x00"),
	// sACK
	[]byte("\xd8\x5e\xd3\x43\x03\xeb\x28\xcd\xc1\x05\x4d\xbb\x08\x00\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\xb6\x5b\xc0\xa8\x01\x91\xc0\xa8\x01\x93\x04\xd2\x84\x96\xbe\x6e\x4c\x28\x5e\x72\x2b\x97\x50\x10\x10\x00\xfd\x56\x00\x00\x00\x00\x00\x00\x00\x00"),
}

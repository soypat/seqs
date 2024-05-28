package seqs

import (
	"errors"

	"github.com/soypat/seqs/internal"
)

// RingTx is a ring buffer with retransmission queue functionality added.
type RingTx struct {
	// rawbuf contains the ring buffer of ordered bytes. It should be the size of the window.
	rawbuf []byte
	// packets contains
	packets []ringidx
	// firstPkt is the index of the oldest packet in the packets field.
	firstPkt  int
	lastPkt   int
	unsentoff int
	unsentend int
}

// BufferedUnsent
func (tx *RingTx) BufferedUnsent() int {
	r := tx.unsentRing()
	return r.Buffered()
}

// BufferedSent
func (tx *RingTx) BufferedSent() int {
	r := tx.sentRing()
	return r.Buffered()
}

// Write writes data to the underlying unsent data ring buffer.
func (tx *RingTx) Write(b []byte) (int, error) {
	first := tx.packets[tx.firstPkt]
	r := tx.unsentRing()
	if first.off < 0 {
		// No packets in queue case.
		return r.Write(b)
	}
	return r.WriteLimited(b, first.off)
}

// ReadPacket reads from the unsent data ring buffer and generates a new packet segment.
// It fails if the sent packet queue is full.
func (tx *RingTx) ReadPacket(b []byte) (int, error) {
	nxtpkt := (tx.lastPkt + 1) % len(tx.packets)
	if tx.firstPkt == nxtpkt {
		return 0, errors.New("packet queue full")
	}

	r := tx.unsentRing()
	start := r.Off
	n, err := r.Read(b)
	if err != nil {
		return n, err
	}
	tx.packets[nxtpkt].off = start
	tx.packets[nxtpkt].end = r.Off
	tx.packets[nxtpkt].seq = tx.packets[tx.lastPkt].seq + Value(tx.packets[tx.lastPkt].end-tx.packets[tx.lastPkt].off)
	tx.lastPkt = nxtpkt
	tx.unsentoff = r.Off
	return n, nil
}

// IsQueueFull returns true if the sent packet queue is full in which
// case a call to ReadPacket is guaranteed to fail.
func (tx *RingTx) IsQueueFull() bool {
	return tx.firstPkt == (tx.lastPkt+1)%len(tx.packets)
}

// RecvSegment processes an incoming segment and updates the sent packet queue
func (tx *RingTx) RecvACK(ack Value) error {
	i := tx.firstPkt
	for {
		pkt := &tx.packets[i]
		if ack > pkt.seq {
			// Packet was received by remote. Mark it as acked.
			pkt.off = -1
			tx.firstPkt++
			continue
		}
		if i == tx.lastPkt {
			break
		}
		i = (i + 1) % len(tx.packets)
	}
	return nil
}

// unsentOff returns the offset of start of unsent data into rawbuf.
func (tx *RingTx) unsentOff() int {
	return tx.unsentoff
}

func (tx *RingTx) unsentRing() internal.Ring {
	return internal.Ring{Buf: tx.rawbuf, Off: tx.unsentoff, End: tx.unsentend}
}

func (tx *RingTx) sentRing() internal.Ring {
	first := tx.packets[tx.firstPkt]
	if first.off < 0 {
		return internal.Ring{Buf: tx.rawbuf}
	}
	last := tx.packets[tx.lastPkt]
	return internal.Ring{Buf: tx.rawbuf, Off: first.off, End: last.end}
}

// ringidx represents packet data inside RingTx
type ringidx struct {
	// off is data start offset of packet data inside buf.
	off int
	// end is the ringed data end offset, non-inclusive.
	end int
	// seq is the sequence number of the packet.
	seq Value
	// acked flags if this packet has been acknowledged. Useful for SACK (selective acknowledgement)
	// acked bool
}

type ringPacket struct {
	ring internal.Ring
	seq  Value
}

func (r *RingTx) packet(i int) (ringidx, error) {
	if i > len(r.packets) {
		return ringidx{}, errors.New("oob idx")
	}
	i = (i + r.firstPkt) % len(r.packets)
	p := r.packets[i]
	if p.off < 0 {
		return ringidx{}, errors.New("no packets")
	}
	return p, nil
}

func (r *RingTx) ringpacket(i int) (ringPacket, error) {
	p, err := r.packet(i)
	if err != nil {
		return ringPacket{}, err
	}
	ring := internal.Ring{Buf: r.rawbuf, Off: p.off, End: p.end}
	rp := ringPacket{
		ring: ring,
		seq:  p.seq,
	}
	return rp, nil
}

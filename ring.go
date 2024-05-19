package seqs

import "github.com/soypat/seqs/internal"

type RingTx struct {
	// buf contains the ring buffer of ordered bytes. It should be the size of the window.
	buf []byte
	// packets contains
	packets []ringidx
	// startPacketIdx is the index of the oldest packet in the Tx queue.
	startPacketIdx int
	startPacketAck Value
}

// ringidx represents packet data inside RingTx
type ringidx struct {
	// off is data start offset of packet data inside buf.
	off int
	// acked flags if this packet has been acknowledged.
	acked bool
}

type ringPacket struct {
	ring  internal.Ring
	ack   Value
	acked bool
}

func (r *RingTx) packet(i int) (ringPacket, error) {
	i = (i + r.startPacketIdx) % len(r.packets)
	p := r.packets[i]
	pnext := r.packets[i%(len(r.packets))]
	ring := internal.Ring{Buf: r.buf, Off: p.off, End: pnext.off}
	rp := ringPacket{
		ring:  ring,
		ack:   r.startPacketAck + Value(p.off),
		acked: p.acked,
	}

	return rp, nil
}

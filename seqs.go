package seqs

import (
	"strconv"
	"unsafe"
)

// StringExchange returns a string representation of a segment exchange over
// a network in RFC9293 styled visualization. invertDir inverts the arrow directions.
// i.e:
//
//	SynSent --> <SEQ=300><ACK=91>[SYN,ACK]  --> SynRcvd
func StringExchange(seg Segment, A, B State, invertDir bool) string {
	b := make([]byte, 0, 64)
	b = appendVisualization(b, seg, A, B, invertDir)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// appendVisualization appends a RFC9293 styled visualization of exchange to buf.
// i.e:
//
//	SynSent --> <SEQ=300><ACK=91>[SYN,ACK]  --> SynRcvd
func appendVisualization(buf []byte, seg Segment, A, B State, invertDir bool) []byte {
	const emptySpaces = "            "
	buf = buf[len(buf):] // clip off any previous data so we work with our data only.
	appendVal := func(buf []byte, name string, i Value) []byte {
		buf = append(buf, '<')
		buf = append(buf, name...)
		buf = append(buf, '=')
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, '>')
		return buf
	}

	dirSep := []byte(" --> ")
	if invertDir {
		dirSep = []byte(" <-- ")
	}
	astr := A.String()
	buf = append(buf, astr...)
	buf = append(buf, emptySpaces[:11-len(astr)]...) // Fill up to 11 characters
	buf = append(buf, dirSep...)
	buf = appendVal(buf, "SEQ", seg.SEQ)
	buf = appendVal(buf, "ACK", seg.ACK)
	if seg.DATALEN > 0 {
		buf = appendVal(buf, "DATA", Value(seg.DATALEN))
	}
	buf = append(buf, seg.Flags.String()...)
	if len(buf) < 44 {
		buf = append(buf, emptySpaces[:44-len(buf)]...) // Fill up to 44 characters
	}
	buf = append(buf, dirSep...)
	buf = append(buf, B.String()...)
	return buf
}

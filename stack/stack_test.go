package stack_test

import (
	"testing"

	"github.com/soypat/seqs/stack"
)

func TestAB(t *testing.T) {
	var (
		macA = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipA  = []byte{192, 168, 1, 1}
		macB = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
		ipB  = []byte{192, 168, 1, 2}

		// pipeA2B [2024]byte
	)
	A := stack.NewStack(stack.StackConfig{
		MAC:         macA,
		IP:          ipA,
		MaxTCPConns: 1,
	})
	B := stack.NewStack(stack.StackConfig{
		MAC:         macB,
		IP:          ipB,
		MaxTCPConns: 1,
	})

	_ = B

	A.OpenTCP(80, func(b []byte, t *stack.TCPPacket) (int, error) {

		return 0, nil
	})

}

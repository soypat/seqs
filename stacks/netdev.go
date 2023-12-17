package stacks

import (
	"errors"
	"net/netip"
	"time"

	"tinygo.org/x/drivers/netdev"
)

type socketer interface {
	Connect(ip netip.AddrPort) error
	Bind(ip netip.AddrPort) error
	Listen(backlog int) error
	Accept() (newSock socketer, peer netip.AddrPort, err error)
}

type sockets map[int]socketer // keyed by sockfd [1-n]

func (ps *PortStack) GetHostByName(name string) (netip.Addr, error) {
	// Use ParseAddr to test if name is in dotted decimal ("10.0.0.1")
	addr, err := netip.ParseAddr(name)
	if err != nil {
		// TODO Parse err, need to resolve host name to ip
		return netip.Addr{}, netdev.ErrHostUnknown
	}
	return addr, nil
}

func (ps *PortStack) _newSockfd() int {
	var sockfd int

	// Find next available sockfd number, starting at 1
	for sockfd = 1;; sockfd++ {
		_, taken := ps.sockets[sockfd]
		if !taken {
			break
		}
	}
	return sockfd
}

func (ps *PortStack) Socket(domain int, stype int, protocol int) (int, error) {

	println("Socket domain", domain, "stype", stype, "protocol", protocol)

	ps.socketsMu.Lock()
	defer ps.socketsMu.Unlock()

	switch domain {
	case netdev.AF_INET:
	default:
		return -1, netdev.ErrFamilyNotSupported
	}

	switch {
	case protocol == netdev.IPPROTO_TCP && stype == netdev.SOCK_STREAM:
	case protocol == netdev.IPPROTO_UDP && stype == netdev.SOCK_DGRAM:
	default:
		return -1, netdev.ErrProtocolNotSupported
	}

	sockfd := ps._newSockfd()

	switch protocol {
	case netdev.IPPROTO_TCP:
		const socketBuf = 256
		sock, err := NewTCPSocket(ps, TCPSocketConfig{
			TxBufSize: socketBuf,
			RxBufSize: socketBuf,
		})
		if err != nil {
			return -1, err
		}
		ps.sockets[sockfd] = sock
	default:
		return -1, netdev.ErrProtocolNotSupported
	}

	return sockfd, nil
}

func (ps *PortStack) Bind(sockfd int, ip netip.AddrPort) error {

	println("Bind sockfd", sockfd, "ip", ip.String())

	ps.socketsMu.RLock()
	defer ps.socketsMu.RUnlock()

	sock, found := ps.sockets[sockfd]
	if !found {
		return netdev.ErrNoSocket
	}

	return sock.Bind(ip)
}

func (ps *PortStack) Connect(sockfd int, host string, ip netip.AddrPort) error {

	println("Connect sockfd", sockfd, "host", host, "ip", ip.String())

	ps.socketsMu.RLock()
	defer ps.socketsMu.RUnlock()

	// TODO: for now fail host name connects
	if host != "" {
		return netdev.ErrNotSupported
	}

	sock, found := ps.sockets[sockfd]
	if !found {
		return netdev.ErrNoSocket
	}

	return sock.Connect(ip)
}

func (ps *PortStack) Listen(sockfd int, backlog int) error {

	println("Listen sockfd", sockfd, "backlog", backlog)

	ps.socketsMu.RLock()
	defer ps.socketsMu.RUnlock()

	sock, found := ps.sockets[sockfd]
	if !found {
		return netdev.ErrNoSocket
	}

	return sock.Listen(backlog)
}

// TODO the ip arg is a return arg and should return the address of the peer socket
// TODO this will require an update to Netdever interface...
//func (ps *PortStack) Accept(sockfd int) (int, netip.AddrPort, error) {
func (ps *PortStack) Accept(sockfd int, ip netip.AddrPort) (int, error) {

	println("Accept sockfd", sockfd)

	ps.socketsMu.Lock()
	defer ps.socketsMu.Unlock()

	sock, found := ps.sockets[sockfd]
	if !found {
		return -1, netdev.ErrNoSocket
	}

	//newSock, peer, err := sock.Accept()
	newSock, _, err := sock.Accept()
	if err != nil {
		return -1, err
	}

	newSockfd := ps._newSockfd()
	ps.sockets[newSockfd] = newSock

	println("Accept sockfd", sockfd, "--> New sockfd", newSockfd)
	//TODO return newSockfd, peer, nil
	return newSockfd, nil
}

func (ps *PortStack) Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	ps.socketsMu.RLock()
	defer ps.socketsMu.RUnlock()

	return 0, errors.New("Send not implemented")
}

func (ps *PortStack) Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	return 0, errors.New("Recv not implemented")
}

func (ps *PortStack) Close(sockfd int) error {
	ps.socketsMu.Lock()
	defer ps.socketsMu.Unlock()

	return errors.New("Close not implemented")
}

func (ps *PortStack) SetSockOpt(sockfd int, level int, opt int, value interface{}) error {
	ps.socketsMu.RLock()
	defer ps.socketsMu.RUnlock()

	return errors.New("SetSockOpt not implemented")
}

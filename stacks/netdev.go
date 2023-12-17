package stacks

import (
	"errors"
	"net/netip"
	"time"
)


func (ps *PortStack) GetHostByName(name string) (netip.Addr, error) {
	return netip.Addr{}, errors.New("GetHostByName not implemented")
}

func (ps *PortStack) Socket(domain int, stype int, protocol int) (int, error) {
	return -1, errors.New("Socket not implemented")
}

func (ps *PortStack) Bind(sockfd int, ip netip.AddrPort) error {
	return errors.New("Bind not implemented")
}

func (ps *PortStack) Connect(sockfd int, host string, ip netip.AddrPort) error {
	return errors.New("Connect not implemented")
}

func (ps *PortStack) Listen(sockfd int, backlog int) error {
	return errors.New("Listen not implemented")
}

func (ps *PortStack) Accept(sockfd int, ip netip.AddrPort) (int, error) {
	return -1, errors.New("Accept not implemented")
}

func (ps *PortStack) Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	return 0, errors.New("Send not implemented")
}

func (ps *PortStack) Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	return 0, errors.New("Recv not implemented")
}

func (ps *PortStack) Close(sockfd int) error {
	return errors.New("Close not implemented")
}

func (ps *PortStack) SetSockOpt(sockfd int, level int, opt int, value interface{}) error {
	return errors.New("SetSockOpt not implemented")
}

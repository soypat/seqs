# seqs
[![go.dev reference](https://pkg.go.dev/badge/github.com/soypat/seqs)](https://pkg.go.dev/github.com/soypat/seqs)
[![Go Report Card](https://goreportcard.com/badge/github.com/soypat/seqs)](https://goreportcard.com/report/github.com/soypat/seqs)
[![codecov](https://codecov.io/gh/soypat/seqs/branch/main/graph/badge.svg)](https://codecov.io/gh/soypat/seqs)
[![Go](https://github.com/soypat/seqs/actions/workflows/go.yml/badge.svg)](https://github.com/soypat/seqs/actions/workflows/go.yml)
[![sourcegraph](https://sourcegraph.com/github.com/soypat/seqs/-/badge.svg)](https://sourcegraph.com/github.com/soypat/seqs?badge)

`seqs` is what is commonly referred to as a userspace IP implementation. It handles:
* Ethernet protocol
* IP packet marshalling to sub-protocols:
    * ARP requests and responses
    * UDP packet handling
    * DHCP client requests and DHCP server
    * TCP connections over IP with support for multiple listeners on same port. These implement [net.Conn](https://pkg.go.dev/net#Conn) and [net.Listener](https://pkg.go.dev/net#Listener) interfaces. See [`stacks/tcpconn.go`](./stacks/tcpconn.go)


### Example of use

```go
stack := stacks.NewPortStack(stacks.PortStackConfig{
    MAC:             MAC,
    MaxOpenPortsTCP: 1,
    MaxOpenPortsUDP: 1,
    MTU:             2048,
})
// Static IP setting.
ip := netip.AddrFrom4([4]byte{192, 168, 1, 45}) 
stack.SetAddr(ip)

// Or can request an address via DHCP.
dhcpClient := stacks.NewDHCPClient(stack, dhcp.DefaultClientPort)
err = dhcpClient.BeginRequest(stacks.DHCPRequestConfig{
    RequestedAddr: netip.AddrFrom4([4]byte{192, 168, 1, 69}),
    Xid:           0x12345678,
    Hostname:      "tinygo-pico",
})

for !dhcpClient.Done() {
    time.Sleep(time.Second / 2)
}

offeredIP := dhcpClient.Offer()
fmt.Println("got offer:", offeredIP)
stack.SetAddr(offeredIP)
```

How to use `seqs`
```sh
go mod download github.com/soypat/seqs@latest
```


#### History - Precursors to seqs
Before `seqs` there was:

* [`ether-swtch`](https://github.com/soypat/ether-swtch) - First known instance of a (barely) working TCP/IP stack in Go working on embedded systems, circa June 2021. Could blink an Arduino UNO's LED via HTTP (!). Famously bad design, code, performance, readability.
* [`dgrams`](https://github.com/soypat/dgrams) - Library prepared for Pico W's wifi chip. Already shows similarities with `seqs`. Circa May 2023.
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
    * HTTP: Algorithm to reuse heap memory between requests and avoid allocations. See `httpx` package
    * NTP client for resolving time offset to a NTP server

## ⚠️ Developer note ⚠️
This package may be superceded by https://github.com/soypat/lneto. 

### What does this mean?
Rest easy, the high-level API of `seqs` will be able to make use of `lneto`, so this package will be supported in the future.

Low level bits of `seqs` may break or be completely removed such as anything inside [`eth`](./eth) package.

Below is a list of future proof APIs in seqs (their internal functioning is subject to change):
- [`stacks.TCPConn`](./stacks/tcpconn.go)
- [`stacks.TCPListener`](./stacks/tcplistener.go)
- [`stacks.DNSClient`](./stacks/dns_client.go)
- [`stacks.DHCPClient`](./stacks/dhcp_client.go)
- [`stacks.NTPClient`](./stacks/ntp_client.go)
- [`stacks.PortStack`](./stacks/portstack.go) - HandleEth, RecvEth methods will remain. Open* and Close* methods will remain. May require different initialization. 

Use above APIs if you plan on using most up to date version of `seqs` in the future.

### Why?
seqs has accumulated technical debt due to its design.`lneto` is being designed with ease of testing as a priority. 
`lneto` features:
- Zero copy package processing for performance gains
- Packet framing design
  - Variable length headers included in frame type logic, no longer part of client/server implementation
  - Huge reduction in stack memory usage. Much easier to avoid heap usage
  - Early stack implementations are shown to be much simpler to write and read by humans
- Client and Server logic is moved closer to frame logic, better separation of responsibility

## Example of use

```go
// stack works by having access to Ethernet packet sending
// and processing. NIC is our physical link to the internet.
var NIC NetworkInterfaceCard = getNIC()

stack := stacks.NewPortStack(stacks.PortStackConfig{
    MAC:             MAC,
    MaxOpenPortsTCP: 1,
    MaxOpenPortsUDP: 1,
    MTU:             2048,
})
// stack.RecvEth should be called on receiving an ethernet packet. It should NOT block.
NIC.SetRecvEthHandle(stack.RecvEth)

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
if err != nil {
    panic(err)
}

fmt.Println("Start DHCP...")
for !dhcpClient.Done() {
    doNICPoll(NIC)
    time.Sleep(time.Second / 10)
}

offeredIP := dhcpClient.Offer()
fmt.Println("got offer:", offeredIP)
stack.SetAddr(offeredIP)
```

How to use `seqs`
```sh
go mod download github.com/soypat/seqs@latest
```


## History - Precursors to seqs
Before `seqs` there was:

* [`ether-swtch`](https://github.com/soypat/ether-swtch) - First known instance of a (barely) working TCP/IP stack in Go working on embedded systems, circa June 2021. Could blink an Arduino UNO's LED via HTTP (!). Famously bad design, code, performance, readability.
* [`dgrams`](https://github.com/soypat/dgrams) - Library prepared for Pico W's wifi chip. Already shows similarities with `seqs`. Circa May 2023.

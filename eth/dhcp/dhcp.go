package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	sizeSName    = 64  // Server name, part of BOOTP too.
	sizeBootFile = 128 // Boot file name, Legacy.
	SizeHeader   = 44
	// Magic Cookie offset measured from the start of the UDP payload.
	MagicCookieOffset = SizeHeader + sizeSName + sizeBootFile
	// Expected Magic Cookie value.
	MagicCookie uint32 = 0x63825363
	// DHCP Options offset measured from the start of the UDP payload.
	OptionsOffset = MagicCookieOffset + 4

	DefaultClientPort = 68
	DefaultServerPort = 67
)

type Option struct {
	Num  OptNum
	Data []byte
}

func (opt *Option) String() string {
	return opt.Num.String() + ":" + fmt.Sprint(opt.Data)
}

func (opt *Option) Encode(dst []byte) (int, error) {
	if len(opt.Data) > 255 {
		return 0, errors.New("DHCP option data too long")
	} else if len(dst) < 2+len(opt.Data) {
		return 0, errors.New("DHCP option buffer too short")
	}
	_ = dst[2+len(opt.Data)]
	dst[0] = byte(opt.Num)
	dst[1] = byte(len(opt.Data))
	copy(dst[2:], opt.Data)
	return 2 + len(opt.Data), nil
}

type OptNum uint8

// DHCP options. Taken from https://help.sonicwall.com/help/sw/eng/6800/26/2/3/content/Network_DHCP_Server.042.12.htm.
//
//go:generate stringer -type=OptNum -trimprefix=Opt
const (
	OptWordAligned                 OptNum = 0
	OptSubnetMask                  OptNum = 1
	OptTimeOffset                  OptNum = 2  // Time offset in seconds from UTC
	OptRouter                      OptNum = 3  // N/4 router addresses
	OptTimeServers                 OptNum = 4  // N/4 time server addresses
	OptNameServers                 OptNum = 5  // N/4 IEN-116 server addresses
	OptDNSServers                  OptNum = 6  // N/4 DNS server addresses
	OptLogServers                  OptNum = 7  // N/4 logging server addresses
	OptCookieServers               OptNum = 8  // N/4 quote server addresses
	OptLPRServers                  OptNum = 9  // N/4 printer server addresses
	OptImpressServers              OptNum = 10 // N/4 impress server addresses
	OptRLPServers                  OptNum = 11 // N/4 RLP server addresses
	OptHostName                    OptNum = 12 // Hostname string
	OptBootFileSize                OptNum = 13 // Size of boot file in 512 byte chunks
	OptMeritDumpFile               OptNum = 14 // Client to dump and name of file to dump to
	OptDomainName                  OptNum = 15 // The DNS domain name of the client
	OptSwapServer                  OptNum = 16 // Swap server addresses
	OptRootPath                    OptNum = 17 // Path name for root disk
	OptExtensionFile               OptNum = 18 // Patch name for more BOOTP info
	OptIPLayerForwarding           OptNum = 19 // Enable or disable IP forwarding
	OptSrcrouteenabler             OptNum = 20 // Enable or disable source routing
	OptPolicyFilter                OptNum = 21 // Routing policy filters
	OptMaximumDGReassemblySize     OptNum = 22 // Maximum datagram reassembly size
	OptDefaultIPTTL                OptNum = 23 // Default IP time-to-live
	OptPathMTUAgingTimeout         OptNum = 24 // Path MTU aging timeout
	OptMTUPlateau                  OptNum = 25 // Path MTU plateau table
	OptInterfaceMTUSize            OptNum = 26 // Interface MTU size
	OptAllSubnetsAreLocal          OptNum = 27 // All subnets are local
	OptBroadcastAddress            OptNum = 28 // Broadcast address
	OptPerformMaskDiscovery        OptNum = 29 // Perform mask discovery
	OptProvideMasktoOthers         OptNum = 30 // Provide mask to others
	OptPerformRouterDiscovery      OptNum = 31 // Perform router discovery
	OptRouterSolicitationAddress   OptNum = 32 // Router solicitation address
	OptStaticRoutingTable          OptNum = 33 // Static routing table
	OptTrailerEncapsulation        OptNum = 34 // Trailer encapsulation
	OptARPCacheTimeout             OptNum = 35 // ARP cache timeout
	OptEthernetEncapsulation       OptNum = 36 // Ethernet encapsulation
	OptDefaultTCPTimetoLive        OptNum = 37 // Default TCP time to live
	OptTCPKeepaliveInterval        OptNum = 38 // TCP keepalive interval
	OptTCPKeepaliveGarbage         OptNum = 39 // TCP keepalive garbage
	OptNISDomainName               OptNum = 40 // NIS domain name
	OptNISServerAddresses          OptNum = 41 // NIS server addresses
	OptNTPServersAddresses         OptNum = 42 // NTP servers addresses
	OptVendorSpecificInformation   OptNum = 43 // Vendor specific information
	OptNetBIOSNameServer           OptNum = 44 // NetBIOS name server
	OptNetBIOSDatagramDistribution OptNum = 45 // NetBIOS datagram distribution
	OptNetBIOSNodeType             OptNum = 46 // NetBIOS node type
	OptNetBIOSScope                OptNum = 47 // NetBIOS scope
	OptXWindowFontServer           OptNum = 48 // X window font server
	OptXWindowDisplayManager       OptNum = 49 // X window display manager
	OptRequestedIPaddress          OptNum = 50 // Requested IP address
	OptIPAddressLeaseTime          OptNum = 51 // IP address lease time
	OptOptionOverload              OptNum = 52 // Overload “sname” or “file”
	OptMessageType                 OptNum = 53 // DHCP message type.
	OptServerIdentification        OptNum = 54 // DHCP server identification
	OptParameterRequestList        OptNum = 55 // Parameter request list
	OptMessage                     OptNum = 56 // DHCP error message
	OptMaximumMessageSize          OptNum = 57 // DHCP maximum message size
	OptRenewTimeValue              OptNum = 58 // DHCP renewal (T1) time
	OptRebindingTimeValue          OptNum = 59 // DHCP rebinding (T2) time
	OptClientIdentifier            OptNum = 60 // Client identifier
	OptClientIdentifier1           OptNum = 61 // Client identifier
)

type Op byte

const (
	OpRequest Op = 1
	OpReply   Op = 2
)

// HeaderV4 specifies the first 44 bytes of a DHCP packet payload. It does
// not include BOOTP, magic cookie and options.
// Reference: https://lists.gnu.org/archive/html/lwip-users/2012-12/msg00016.html
type HeaderV4 struct {
	OP Op // 0:1
	// Htype is the hardware address type. 1 for Ethernet.
	HType byte   // 1:2
	HLen  uint8  // 2:3
	HOps  uint8  // 3:4
	Xid   uint32 // 4:8
	Secs  uint16 // 8:10
	Flags uint16 // 10:12
	// CIAddr is the client IP address. If the client has not obtained an IP
	// address yet, this field is set to 0.
	CIAddr [4]byte // 12:16
	// YIAddr is the IP address offered by the server to the client.
	YIAddr [4]byte // 16:20
	// SIAddr is the IP address of the next server to use in bootstrap. This
	// field is used in DHCPOFFER and DHCPACK messages.
	SIAddr [4]byte // 20:24
	// GIAddr is the gateway IP address.
	GIAddr [4]byte // 24:28
	// CHAddr is the client hardware address. Can be up to 16 bytes in length but
	// is usually 6 bytes for Ethernet.
	CHAddr [16]byte // 28:44
	// BOOTP, Magic Cookie, and DHCP Options not included.
	// LegacyBOOTP [192]byte
	// Magic       [4]byte // 0x63,0x82,0x53,0x63
	// Options     [275...]byte // as of RFC2131 it is variable length
}

func (dhdr *HeaderV4) Put(dst []byte) {
	_ = dst[43]
	dst[0] = byte(dhdr.OP)
	dst[1] = dhdr.HType
	dst[2] = dhdr.HLen
	dst[3] = dhdr.HOps
	binary.BigEndian.PutUint32(dst[4:8], dhdr.Xid)
	binary.BigEndian.PutUint16(dst[8:10], dhdr.Secs)
	binary.BigEndian.PutUint16(dst[10:12], dhdr.Flags)
	copy(dst[12:16], dhdr.CIAddr[:])
	copy(dst[16:20], dhdr.YIAddr[:])
	copy(dst[20:24], dhdr.SIAddr[:])
	copy(dst[24:28], dhdr.GIAddr[:])
	copy(dst[28:44], dhdr.CHAddr[:])
}

func DecodeHeaderV4(src []byte) (d HeaderV4) {
	_ = src[43]
	d.OP = Op(src[0])
	d.HType = src[1]
	d.HLen = src[2]
	d.HOps = src[3]
	d.Xid = binary.BigEndian.Uint32(src[4:8])
	d.Secs = binary.BigEndian.Uint16(src[8:10])
	d.Flags = binary.BigEndian.Uint16(src[10:12])
	copy(d.CIAddr[:], src[12:16])
	copy(d.YIAddr[:], src[16:20])
	copy(d.SIAddr[:], src[20:24])
	copy(d.GIAddr[:], src[24:28])
	copy(d.CHAddr[:], src[28:44])
	return d
}

func (dhdr *HeaderV4) String() (s string) {
	s = "DHCP op=" + strconv.Itoa(int(dhdr.OP)) + " "
	if dhdr.CIAddr != [4]byte{} {
		s += "ciaddr=" + net.IP(dhdr.CIAddr[:]).String() + " "
	}
	if dhdr.YIAddr != [4]byte{} {
		s += "yiaddr=" + net.IP(dhdr.YIAddr[:]).String() + " "
	}
	if dhdr.SIAddr != [4]byte{} {
		s += "siaddr=" + net.IP(dhdr.SIAddr[:]).String() + " "
	}
	if dhdr.GIAddr != [4]byte{} {
		s += "giaddr=" + net.IP(dhdr.GIAddr[:]).String() + " "
	}
	if dhdr.CHAddr != [16]byte{} && dhdr.HLen < 16 && dhdr.HLen > 0 {
		s += "chaddr=" + net.HardwareAddr(dhdr.CHAddr[:dhdr.HLen]).String() + " "
	}
	return s
}

func ForEachOption(udpPayload []byte, fn func(opt Option) error) error {
	if fn == nil {
		return errors.New("nil function to parse DHCP")
	}
	// Parse DHCP options.
	ptr := OptionsOffset
	if ptr >= len(udpPayload) {
		return errors.New("short payload to parse DHCP options")
	}
	for ptr+1 < len(udpPayload) {
		if int(udpPayload[ptr+1]) >= len(udpPayload) {
			return errors.New("DHCP option length exceeds payload")
		}
		optnum := OptNum(udpPayload[ptr])
		if optnum == 0xff {
			break
		} else if optnum == OptWordAligned {
			ptr++
			continue
		}
		optlen := udpPayload[ptr+1]
		optionData := udpPayload[ptr+2 : ptr+2+int(optlen)]
		if err := fn(Option{optnum, optionData}); err != nil {
			return err
		}
		ptr += int(optlen) + 2
	}
	return nil
}

//go:generate stringer -type=MessageType -trimprefix=Msg
type MessageType uint8

const (
	MsgDiscover MessageType = iota + 1
	MsgOffer
	MsgRequest
	MsgDecline
	MsgAck
	MsgNak
	MsgRelease
	MsgInform
)

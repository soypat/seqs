package eth

// Ethertype values. From: http://en.wikipedia.org/wiki/Ethertype
//
//go:generate stringer -type=EtherType -trimprefix=EtherType
const (
	EtherTypeIPv4                EtherType = 0x0800
	EtherTypeARP                 EtherType = 0x0806
	EtherTypeWakeOnLAN           EtherType = 0x0842
	EtherTypeTRILL               EtherType = 0x22F3
	EtherTypeDECnetPhase4        EtherType = 0x6003
	EtherTypeRARP                EtherType = 0x8035
	EtherTypeAppleTalk           EtherType = 0x809B
	EtherTypeAARP                EtherType = 0x80F3
	EtherTypeIPX1                EtherType = 0x8137
	EtherTypeIPX2                EtherType = 0x8138
	EtherTypeQNXQnet             EtherType = 0x8204
	EtherTypeIPv6                EtherType = 0x86DD
	EtherTypeEthernetFlowControl EtherType = 0x8808
	EtherTypeIEEE802_3           EtherType = 0x8809
	EtherTypeCobraNet            EtherType = 0x8819
	EtherTypeMPLSUnicast         EtherType = 0x8847
	EtherTypeMPLSMulticast       EtherType = 0x8848
	EtherTypePPPoEDiscovery      EtherType = 0x8863
	EtherTypePPPoESession        EtherType = 0x8864
	EtherTypeJumboFrames         EtherType = 0x8870
	EtherTypeHomePlug1_0MME      EtherType = 0x887B
	EtherTypeIEEE802_1X          EtherType = 0x888E
	EtherTypePROFINET            EtherType = 0x8892
	EtherTypeHyperSCSI           EtherType = 0x889A
	EtherTypeAoE                 EtherType = 0x88A2
	EtherTypeEtherCAT            EtherType = 0x88A4
	EtherTypeEthernetPowerlink   EtherType = 0x88AB
	EtherTypeLLDP                EtherType = 0x88CC
	EtherTypeSERCOS3             EtherType = 0x88CD
	EtherTypeHomePlugAVMME       EtherType = 0x88E1
	EtherTypeMRP                 EtherType = 0x88E3
	EtherTypeIEEE802_1AE         EtherType = 0x88E5
	EtherTypeIEEE1588            EtherType = 0x88F7
	EtherTypeIEEE802_1ag         EtherType = 0x8902
	EtherTypeFCoE                EtherType = 0x8906
	EtherTypeFCoEInit            EtherType = 0x8914
	EtherTypeRoCE                EtherType = 0x8915
	EtherTypeCTP                 EtherType = 0x9000
	EtherTypeVeritasLLT          EtherType = 0xCAFE
	EtherTypeVLAN                EtherType = 0x8100
	EtherTypeServiceVLAN         EtherType = 0x88a8
	// minEthPayload is the minimum payload size for an Ethernet frame, assuming
	// that no 802.1Q VLAN tags are present.
	minEthPayload = 46
)

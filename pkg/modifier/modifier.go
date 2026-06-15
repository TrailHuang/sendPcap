package modifier

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketModifier holds the rules for modifying packet fields
type PacketModifier struct {
	SrcMAC   net.HardwareAddr
	DstMAC   net.HardwareAddr
	VLAN     int    // 0 = no modification
	SrcIP    net.IP // nil = no modification
	DstIP    net.IP // nil = no modification
	SrcPort  int    // 0 = no modification
	DstPort  int    // 0 = no modification
	TTL      int    // 0 = no modification
	Protocol int    // 0 = no modification
}

// Modify applies the modification rules to a raw packet and returns the modified bytes
func (m *PacketModifier) Modify(rawPacket []byte, isDownstream bool) ([]byte, error) {
	packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)

	// Extract layers
	var ethLayer *layers.Ethernet
	var ip4Layer *layers.IPv4
	var tcpLayer *layers.TCP
	var udpLayer *layers.UDP
	// dnsLayer is not used in serialization - gopacket's DNS serialization corrupts the data

	if l := packet.Layer(layers.LayerTypeEthernet); l != nil {
		ethLayer = l.(*layers.Ethernet)
	}
	if l := packet.Layer(layers.LayerTypeIPv4); l != nil {
		ip4Layer = l.(*layers.IPv4)
	}
	if l := packet.Layer(layers.LayerTypeTCP); l != nil {
		tcpLayer = l.(*layers.TCP)
	}
	if l := packet.Layer(layers.LayerTypeUDP); l != nil {
		udpLayer = l.(*layers.UDP)
	}

	if ethLayer == nil {
		return nil, nil // skip non-ethernet packets
	}

	// Modify MAC addresses
	if m.SrcMAC != nil {
		ethLayer.SrcMAC = m.SrcMAC
	}
	if m.DstMAC != nil {
		ethLayer.DstMAC = m.DstMAC
	}

	// Modify IP layer
	if ip4Layer != nil {
		if isDownstream {
			// Downstream: swap src/dst modifications
			if m.DstIP != nil {
				if ip := m.DstIP.To4(); ip != nil {
					ip4Layer.SrcIP = ip
				}
			}
			if m.SrcIP != nil {
				if ip := m.SrcIP.To4(); ip != nil {
					ip4Layer.DstIP = ip
				}
			}
		} else {
			// Upstream: normal direction
			if m.SrcIP != nil {
				if ip := m.SrcIP.To4(); ip != nil {
					ip4Layer.SrcIP = ip
				}
			}
			if m.DstIP != nil {
				if ip := m.DstIP.To4(); ip != nil {
					ip4Layer.DstIP = ip
				}
			}
		}
		if m.TTL > 0 {
			ip4Layer.TTL = uint8(m.TTL)
		}
		if m.Protocol > 0 {
			ip4Layer.Protocol = layers.IPProtocol(m.Protocol)
		}
	}

	// Modify TCP ports
	if tcpLayer != nil {
		if isDownstream {
			// Downstream: swap src/dst port modifications
			if m.DstPort > 0 {
				tcpLayer.SrcPort = layers.TCPPort(m.DstPort)
			}
			if m.SrcPort > 0 {
				tcpLayer.DstPort = layers.TCPPort(m.SrcPort)
			}
		} else {
			// Upstream: normal direction
			if m.SrcPort > 0 {
				tcpLayer.SrcPort = layers.TCPPort(m.SrcPort)
			}
			if m.DstPort > 0 {
				tcpLayer.DstPort = layers.TCPPort(m.DstPort)
			}
		}
		if ip4Layer != nil {
			tcpLayer.SetNetworkLayerForChecksum(ip4Layer)
		}
	}

	// Modify UDP ports
	if udpLayer != nil {
		if isDownstream {
			// Downstream: swap src/dst port modifications
			if m.DstPort > 0 {
				udpLayer.SrcPort = layers.UDPPort(m.DstPort)
			}
			if m.SrcPort > 0 {
				udpLayer.DstPort = layers.UDPPort(m.SrcPort)
			}
		} else {
			// Upstream: normal direction
			if m.SrcPort > 0 {
				udpLayer.SrcPort = layers.UDPPort(m.SrcPort)
			}
			if m.DstPort > 0 {
				udpLayer.DstPort = layers.UDPPort(m.DstPort)
			}
		}
		if ip4Layer != nil {
			udpLayer.SetNetworkLayerForChecksum(ip4Layer)
		}
	}

	// Store raw bytes after the transport layer header for explicit serialization.
	// We use raw packet data instead of layer.Payload to avoid shared backing array
	// issues where SerializeLayers modifies the underlying byte slice during processing.
	// We calculate the exact payload length from IPv4.TotalLength to avoid including
	// Ethernet minimum-frame padding (60 bytes) that gopacket may add.
	var udpPayload []byte
	var tcpPayload []byte
	rawData := packet.Data()
	// ipDataLen = actual IP packet length (excludes Ethernet padding)
	var ipDataLen int
	if ip4Layer != nil {
		ipDataLen = int(ip4Layer.Length) // from IP TotalLength field
	} else {
		ipDataLen = len(rawData) - 14 // fallback: assume 14-byte Ethernet header
	}

	if udpLayer != nil {
		offset := 0
		for _, l := range packet.Layers() {
			if l.LayerType() == layers.LayerTypeUDP {
				offset += len(l.LayerContents()) // only header, not payload
				break
			}
			offset += len(l.LayerContents())
		}
		// IP data starts at offset 14 (after Ethernet header)
		ipEnd := 14 + ipDataLen
		if offset > 0 && offset < ipEnd && ipEnd <= len(rawData) {
			udpPayload = make([]byte, ipEnd-offset)
			copy(udpPayload, rawData[offset:ipEnd])
		}
	}
	// Don't use dnsLayer in serialization - gopacket's DNS serialization corrupts the data
	// The DNS content is already in udpPayload

	if tcpLayer != nil {
		offset := 0
		for _, l := range packet.Layers() {
			if l.LayerType() == layers.LayerTypeTCP {
				offset += len(l.LayerContents()) // only header, not payload
				break
			}
			offset += len(l.LayerContents())
		}
		ipEnd := 14 + ipDataLen
		if offset > 0 && offset < ipEnd && ipEnd <= len(rawData) {
			tcpPayload = make([]byte, ipEnd-offset)
			copy(tcpPayload, rawData[offset:ipEnd])
		}
	}

	// Store non-TCP/UDP IP payload (OSPF, ICMP, GRE, etc.) for explicit serialization
	var ipPayload []byte
	if ip4Layer != nil && tcpLayer == nil && udpLayer == nil {
		offset := 0
		for _, l := range packet.Layers() {
			if l.LayerType() == layers.LayerTypeIPv4 {
				offset += len(l.LayerContents()) // only header, not payload
				break
			}
			offset += len(l.LayerContents())
		}
		ipEnd := 14 + ipDataLen
		if offset > 0 && offset < ipEnd && ipEnd <= len(rawData) {
			ipPayload = make([]byte, ipEnd-offset)
			copy(ipPayload, rawData[offset:ipEnd])
		}
	}

	// Serialize
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Handle VLAN insertion
	if m.VLAN > 0 {
		vlan := &layers.Dot1Q{
			Priority:       0,
			DropEligible:   false,
			VLANIdentifier: uint16(m.VLAN),
			Type:           ethLayer.EthernetType,
		}
		ethLayer.EthernetType = layers.EthernetTypeDot1Q

		layersToSerialize := []gopacket.SerializableLayer{ethLayer, vlan}
		if ip4Layer != nil {
			layersToSerialize = append(layersToSerialize, ip4Layer)
		}
		if udpLayer != nil {
			// UDP takes priority over TCP in encapsulation scenarios (e.g., GTP-U)
			// where gopacket decodes both outer UDP and inner TCP layers
			layersToSerialize = append(layersToSerialize, udpLayer)
			if len(udpPayload) > 0 {
				layersToSerialize = append(layersToSerialize, gopacket.Payload(udpPayload))
			}
		} else if tcpLayer != nil {
			layersToSerialize = append(layersToSerialize, tcpLayer)
			if len(tcpPayload) > 0 {
				layersToSerialize = append(layersToSerialize, gopacket.Payload(tcpPayload))
			}
		} else if len(ipPayload) > 0 {
			// Non-TCP/UDP IP protocols (OSPF, ICMP, GRE, etc.)
			// The IP payload must be serialized explicitly so that gopacket's
			// reverse-order PrependBytes includes it when computing IPv4 TotalLength.
			layersToSerialize = append(layersToSerialize, gopacket.Payload(ipPayload))
		}
		// Only add ApplicationLayer payload if not already added via explicit payload
		if payload := packet.ApplicationLayer(); payload != nil && udpLayer == nil && tcpLayer == nil && len(ipPayload) == 0 {
			layersToSerialize = append(layersToSerialize, gopacket.Payload(payload.Payload()))
		}

		if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
			return nil, err
		}
	} else {
		var layersToSerialize []gopacket.SerializableLayer
		layersToSerialize = append(layersToSerialize, ethLayer)
		if ip4Layer != nil {
			layersToSerialize = append(layersToSerialize, ip4Layer)
		}
		if udpLayer != nil {
			// UDP takes priority over TCP in encapsulation scenarios (e.g., GTP-U)
			// where gopacket decodes both outer UDP and inner TCP layers
			layersToSerialize = append(layersToSerialize, udpLayer)
			if len(udpPayload) > 0 {
				layersToSerialize = append(layersToSerialize, gopacket.Payload(udpPayload))
			}
		} else if tcpLayer != nil {
			layersToSerialize = append(layersToSerialize, tcpLayer)
			if len(tcpPayload) > 0 {
				layersToSerialize = append(layersToSerialize, gopacket.Payload(tcpPayload))
			}
		} else if len(ipPayload) > 0 {
			// Non-TCP/UDP IP protocols (OSPF, ICMP, GRE, etc.)
			// The IP payload must be serialized explicitly so that gopacket's
			// reverse-order PrependBytes includes it when computing IPv4 TotalLength.
			layersToSerialize = append(layersToSerialize, gopacket.Payload(ipPayload))
		}
		// Only add ApplicationLayer payload if not already added via explicit payload
		if payload := packet.ApplicationLayer(); payload != nil && udpLayer == nil && tcpLayer == nil && len(ipPayload) == 0 {
			layersToSerialize = append(layersToSerialize, gopacket.Payload(payload.Payload()))
		}

		if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

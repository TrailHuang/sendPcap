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
func (m *PacketModifier) Modify(rawPacket []byte) ([]byte, error) {
	packet := gopacket.NewPacket(rawPacket, layers.LayerTypeEthernet, gopacket.Default)

	// Extract layers
	var ethLayer *layers.Ethernet
	var ip4Layer *layers.IPv4
	var tcpLayer *layers.TCP
	var udpLayer *layers.UDP

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
		if m.SrcIP != nil {
			ip4Layer.SrcIP = m.SrcIP.To4()
		}
		if m.DstIP != nil {
			ip4Layer.DstIP = m.DstIP.To4()
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
		if m.SrcPort > 0 {
			tcpLayer.SrcPort = layers.TCPPort(m.SrcPort)
		}
		if m.DstPort > 0 {
			tcpLayer.DstPort = layers.TCPPort(m.DstPort)
		}
		if ip4Layer != nil {
			tcpLayer.SetNetworkLayerForChecksum(ip4Layer)
		}
	}

	// Modify UDP ports
	if udpLayer != nil {
		if m.SrcPort > 0 {
			udpLayer.SrcPort = layers.UDPPort(m.SrcPort)
		}
		if m.DstPort > 0 {
			udpLayer.DstPort = layers.UDPPort(m.DstPort)
		}
		if ip4Layer != nil {
			udpLayer.SetNetworkLayerForChecksum(ip4Layer)
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
		if tcpLayer != nil {
			layersToSerialize = append(layersToSerialize, tcpLayer)
		} else if udpLayer != nil {
			layersToSerialize = append(layersToSerialize, udpLayer)
		}
		if payload := packet.ApplicationLayer(); payload != nil {
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
		if tcpLayer != nil {
			layersToSerialize = append(layersToSerialize, tcpLayer)
		} else if udpLayer != nil {
			layersToSerialize = append(layersToSerialize, udpLayer)
		}
		if payload := packet.ApplicationLayer(); payload != nil {
			layersToSerialize = append(layersToSerialize, gopacket.Payload(payload.Payload()))
		}

		if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

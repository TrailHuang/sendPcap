package modifier

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTestPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, ip4, tcp)
	return buf.Bytes()
}

func TestModifyMAC(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 80, 8080)

	newMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	mod := &PacketModifier{SrcMAC: newMAC}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.SrcMAC.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected src MAC aa:bb:cc:dd:ee:ff, got %s", eth.SrcMAC.String())
	}
}

func TestModifyIP(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 80, 8080)

	newIP := net.ParseIP("192.168.1.100").To4()
	mod := &PacketModifier{SrcIP: newIP}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "192.168.1.100" {
		t.Fatalf("expected src IP 192.168.1.100, got %s", ip4.SrcIP.String())
	}
}

func TestModifyPort(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 80, 8080)

	mod := &PacketModifier{SrcPort: 9999, DstPort: 7777}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if int(tcp.SrcPort) != 9999 {
		t.Fatalf("expected src port 9999, got %d", tcp.SrcPort)
	}
	if int(tcp.DstPort) != 7777 {
		t.Fatalf("expected dst port 7777, got %d", tcp.DstPort)
	}
}

func TestModifyTTL(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 80, 8080)

	mod := &PacketModifier{TTL: 128}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.TTL != 128 {
		t.Fatalf("expected TTL 128, got %d", ip4.TTL)
	}
}

func TestModifyVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 80, 8080)

	mod := &PacketModifier{VLAN: 100}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 100 {
		t.Fatalf("expected VLAN ID 100, got %d", vlan.VLANIdentifier)
	}
}

func TestModifyProtocol(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 80, 8080)

	mod := &PacketModifier{Protocol: 17} // UDP

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocol(17) {
		t.Fatalf("expected protocol 17, got %d", ip4.Protocol)
	}
}

func buildTestUDPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, ip4, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

func TestModifyUDPDownstream(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("192.168.1.11").To4()
	dstIP := net.ParseIP("209.87.249.18").To4()

	// Build UDP packet with payload (simulating DNS query)
	pkt := buildTestUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 43966, 53, []byte{0x01, 0x02, 0x03, 0x04})

	mod := &PacketModifier{
		SrcIP:   net.ParseIP("10.0.0.1").To4(),
		DstIP:   net.ParseIP("10.0.0.2").To4(),
		SrcPort: 12345,
		DstPort: 80,
	}

	// Test upstream modification (isDownstream=false)
	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if ip4.SrcIP.String() != "10.0.0.1" {
		t.Fatalf("upstream: expected src IP 10.0.0.1, got %s", ip4.SrcIP.String())
	}
	if ip4.DstIP.String() != "10.0.0.2" {
		t.Fatalf("upstream: expected dst IP 10.0.0.2, got %s", ip4.DstIP.String())
	}
	if int(udp.SrcPort) != 12345 {
		t.Fatalf("upstream: expected src port 12345, got %d", udp.SrcPort)
	}
	if int(udp.DstPort) != 80 {
		t.Fatalf("upstream: expected dst port 80, got %d", udp.DstPort)
	}

	// Verify payload is preserved (UDP payload is in the UDP layer, not ApplicationLayer)
	if len(udp.Payload) != 4 {
		t.Fatalf("upstream: payload not preserved, got %d bytes", len(udp.Payload))
	}

	// Build downstream packet (reversed direction)
	downstreamPkt := buildTestUDPPacket(dstMAC, srcMAC, dstIP, srcIP, 53, 43966, []byte{0x05, 0x06, 0x07, 0x08})

	// Test downstream modification (isDownstream=true)
	// Downstream: src IP should get DstIP (10.0.0.2), dst IP should get SrcIP (10.0.0.1)
	// Downstream: src port should get DstPort (80), dst port should get SrcPort (12345)
	resultDown, err := mod.Modify(downstreamPkt, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packetDown := gopacket.NewPacket(resultDown, layers.LayerTypeEthernet, gopacket.Default)
	ip4Down := packetDown.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpDown := packetDown.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if ip4Down.SrcIP.String() != "10.0.0.2" {
		t.Fatalf("downstream: expected src IP 10.0.0.2 (from DstIP), got %s", ip4Down.SrcIP.String())
	}
	if ip4Down.DstIP.String() != "10.0.0.1" {
		t.Fatalf("downstream: expected dst IP 10.0.0.1 (from SrcIP), got %s", ip4Down.DstIP.String())
	}
	if int(udpDown.SrcPort) != 80 {
		t.Fatalf("downstream: expected src port 80 (from DstPort), got %d", udpDown.SrcPort)
	}
	if int(udpDown.DstPort) != 12345 {
		t.Fatalf("downstream: expected dst port 12345 (from SrcPort), got %d", udpDown.DstPort)
	}

	// Verify payload is preserved in downstream
	if len(udpDown.Payload) != 4 {
		t.Fatalf("downstream: payload not preserved, got %d bytes", len(udpDown.Payload))
	}
}

func TestModifyVLANWithPayload(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	// Test with UDP and payload
	pkt := buildTestUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 1234, 5678, []byte{0xAA, 0xBB, 0xCC})

	mod := &PacketModifier{VLAN: 200}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 200 {
		t.Fatalf("expected VLAN ID 200, got %d", vlan.VLANIdentifier)
	}

	// Verify payload is preserved with VLAN
	// For UDP, ApplicationLayer might be nil, check UDP payload directly
	udpRes := packet.Layer(layers.LayerTypeUDP)
	if udpRes == nil {
		t.Fatal("expected UDP layer")
	}
	udpResult := udpRes.(*layers.UDP)
	if len(udpResult.Payload) != 3 {
		t.Fatalf("payload not preserved with VLAN, got %d bytes", len(udpResult.Payload))
	}
}

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

	result, err := mod.Modify(pkt)
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

	result, err := mod.Modify(pkt)
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

	result, err := mod.Modify(pkt)
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

	result, err := mod.Modify(pkt)
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

	result, err := mod.Modify(pkt)
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

	result, err := mod.Modify(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocol(17) {
		t.Fatalf("expected protocol 17, got %d", ip4.Protocol)
	}
}

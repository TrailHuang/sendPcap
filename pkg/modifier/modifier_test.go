package modifier

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ==================== 辅助构建函数 ====================

// buildTestPacket 构建TCP包
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

// buildTestUDPPacket 构建UDP包
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

// buildTestICMPPacket 构建ICMP包
func buildTestICMPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, icmpType, icmpCode uint8, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
		Id:       1234,
		Seq:      1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, ip4, icmp, gopacket.Payload(payload))
	return buf.Bytes()
}

// buildTestPureEthernetPacket 构建纯二层以太网帧（无IP层）
func buildTestPureEthernetPacket(srcMAC, dstMAC net.HardwareAddr, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetType(0x88B5), // 本地实验协议类型，避免被解析为IP
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, gopacket.Payload(payload))
	return buf.Bytes()
}

// buildTestPureIPPacket 构建纯IP层包（无TCP/UDP）
func buildTestPureIPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, protocol layers.IPProtocol, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: protocol,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, ip4, gopacket.Payload(payload))
	return buf.Bytes()
}

// buildTestVLANPacket 构建带VLAN的TCP包
func buildTestVLANPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, vlanID uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv4,
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
	gopacket.SerializeLayers(buf, opts, eth, vlan, ip4, tcp)
	return buf.Bytes()
}

// buildTestVLANUDPPacket 构建带VLAN的UDP包
func buildTestVLANUDPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, vlanID uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv4,
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
	gopacket.SerializeLayers(buf, opts, eth, vlan, ip4, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

// buildTestVLANICMPPacket 构建带VLAN的ICMP包
func buildTestVLANICMPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, icmpType, icmpCode uint8, vlanID uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeDot1Q,
	}
	vlan := &layers.Dot1Q{
		VLANIdentifier: vlanID,
		Type:           layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
		Id:       1234,
		Seq:      1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, eth, vlan, ip4, icmp, gopacket.Payload(payload))
	return buf.Bytes()
}

// ==================== 测试用例 ====================

// TestModifyMAC 测试修改MAC地址
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

// TestModifyIP 测试修改IP地址
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

// TestModifyPort 测试修改端口
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

// TestModifyTTL 测试修改TTL
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

// TestModifyVLAN 测试插入VLAN（不带VLAN的TCP包）
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

// TestModifyProtocol 测试修改协议号
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

// TestModifyUDPDownstream 测试UDP下游方向修改
func TestModifyUDPDownstream(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("192.168.1.11").To4()
	dstIP := net.ParseIP("209.87.249.18").To4()

	pkt := buildTestUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 43966, 53, []byte{0x01, 0x02, 0x03, 0x04})

	mod := &PacketModifier{
		SrcIP:   net.ParseIP("10.0.0.1").To4(),
		DstIP:   net.ParseIP("10.0.0.2").To4(),
		SrcPort: 12345,
		DstPort: 80,
	}

	// 测试上游修改
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

	// 测试下游修改
	downstreamPkt := buildTestUDPPacket(dstMAC, srcMAC, dstIP, srcIP, 53, 43966, []byte{0x05, 0x06, 0x07, 0x08})
	resultDown, err := mod.Modify(downstreamPkt, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packetDown := gopacket.NewPacket(resultDown, layers.LayerTypeEthernet, gopacket.Default)
	ip4Down := packetDown.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpDown := packetDown.Layer(layers.LayerTypeUDP).(*layers.UDP)

	if ip4Down.SrcIP.String() != "10.0.0.2" {
		t.Fatalf("downstream: expected src IP 10.0.0.2, got %s", ip4Down.SrcIP.String())
	}
	if ip4Down.DstIP.String() != "10.0.0.1" {
		t.Fatalf("downstream: expected dst IP 10.0.0.1, got %s", ip4Down.DstIP.String())
	}
	if int(udpDown.SrcPort) != 80 {
		t.Fatalf("downstream: expected src port 80, got %d", udpDown.SrcPort)
	}
	if int(udpDown.DstPort) != 12345 {
		t.Fatalf("downstream: expected dst port 12345, got %d", udpDown.DstPort)
	}
}

// TestModifyVLANWithPayload 测试带VLAN的UDP包
func TestModifyVLANWithPayload(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

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

	udpRes := packet.Layer(layers.LayerTypeUDP)
	if udpRes == nil {
		t.Fatal("expected UDP layer")
	}
	udpResult := udpRes.(*layers.UDP)
	if len(udpResult.Payload) != 3 {
		t.Fatalf("payload not preserved with VLAN, got %d bytes", len(udpResult.Payload))
	}
}

// ==================== 新增测试用例 ====================

// TestPureEthernetPacket 测试纯二层以太网帧（无IP层）
func TestPureEthernetPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	pkt := buildTestPureEthernetPacket(srcMAC, dstMAC, payload)

	// 修改MAC
	newSrcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	newDstMAC, _ := net.ParseMAC("ff:ee:dd:cc:bb:aa")
	mod := &PacketModifier{SrcMAC: newSrcMAC, DstMAC: newDstMAC}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	if eth.SrcMAC.String() != "11:22:33:44:55:66" {
		t.Fatalf("expected src MAC 11:22:33:44:55:66, got %s", eth.SrcMAC.String())
	}
	if eth.DstMAC.String() != "ff:ee:dd:cc:bb:aa" {
		t.Fatalf("expected dst MAC ff:ee:dd:cc:bb:aa, got %s", eth.DstMAC.String())
	}

	// 纯二层包不应该有IP层
	if packet.Layer(layers.LayerTypeIPv4) != nil {
		t.Fatal("pure ethernet packet should not have IPv4 layer")
	}
}

// TestPureIPPacket 测试纯IP层包（非TCP/UDP，如OSPF等）
func TestPureIPPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte{0x01, 0x02, 0x03, 0x04}

	// 构建纯IP包（协议号89 = OSPF）
	pkt := buildTestPureIPPacket(srcMAC, dstMAC, srcIP, dstIP, 89, payload)

	mod := &PacketModifier{
		SrcIP: net.ParseIP("192.168.1.1").To4(),
		DstIP: net.ParseIP("192.168.1.2").To4(),
		TTL:   100,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	if ip4.SrcIP.String() != "192.168.1.1" {
		t.Fatalf("expected src IP 192.168.1.1, got %s", ip4.SrcIP.String())
	}
	if ip4.DstIP.String() != "192.168.1.2" {
		t.Fatalf("expected dst IP 192.168.1.2, got %s", ip4.DstIP.String())
	}
	if ip4.TTL != 100 {
		t.Fatalf("expected TTL 100, got %d", ip4.TTL)
	}
	if ip4.Protocol != 89 {
		t.Fatalf("expected protocol 89 (OSPF), got %d", ip4.Protocol)
	}
}

// TestICMPPacket 测试ICMP包
func TestICMPPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte("ping data")

	// 构建ICMP Echo Request包
	pkt := buildTestICMPPacket(srcMAC, dstMAC, srcIP, dstIP, 8, 0, payload)

	mod := &PacketModifier{
		SrcIP: net.ParseIP("172.16.0.1").To4(),
		DstIP: net.ParseIP("172.16.0.2").To4(),
		TTL:   255,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

	if ip4.SrcIP.String() != "172.16.0.1" {
		t.Fatalf("expected src IP 172.16.0.1, got %s", ip4.SrcIP.String())
	}
	if ip4.DstIP.String() != "172.16.0.2" {
		t.Fatalf("expected dst IP 172.16.0.2, got %s", ip4.DstIP.String())
	}
	if ip4.TTL != 255 {
		t.Fatalf("expected TTL 255, got %d", ip4.TTL)
	}
	if ip4.Protocol != layers.IPProtocolICMPv4 {
		t.Fatalf("expected ICMP protocol, got %d", ip4.Protocol)
	}
	if icmp.TypeCode.Type() != 8 {
		t.Fatalf("expected ICMP type 8 (Echo Request), got %d", icmp.TypeCode.Type())
	}
	if icmp.TypeCode.Code() != 0 {
		t.Fatalf("expected ICMP code 0, got %d", icmp.TypeCode.Code())
	}
}

// TestICMPPacketWithVLAN 测试带VLAN的ICMP包
func TestICMPPacketWithVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte("ping data")

	// 构建不带VLAN的ICMP包
	pkt := buildTestICMPPacket(srcMAC, dstMAC, srcIP, dstIP, 8, 0, payload)

	// 插入VLAN
	mod := &PacketModifier{
		VLAN:  300,
		SrcIP: net.ParseIP("192.168.10.1").To4(),
		DstIP: net.ParseIP("192.168.10.2").To4(),
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证VLAN
	vlan := packet.Layer(layers.LayerTypeDot1Q)
	if vlan == nil {
		t.Fatal("expected Dot1Q layer")
	}
	vlanLayer := vlan.(*layers.Dot1Q)
	if vlanLayer.VLANIdentifier != 300 {
		t.Fatalf("expected VLAN ID 300, got %d", vlanLayer.VLANIdentifier)
	}

	// 验证IP
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "192.168.10.1" {
		t.Fatalf("expected src IP 192.168.10.1, got %s", ip4.SrcIP.String())
	}

	// 验证ICMP
	icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.TypeCode.Type() != 8 {
		t.Fatalf("expected ICMP type 8, got %d", icmp.TypeCode.Type())
	}
}

// TestTCPPacketWithVLAN 测试带VLAN的TCP包
func TestTCPPacketWithVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	// 构建不带VLAN的TCP包
	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 8080, 80)

	// 插入VLAN并修改
	newSrcMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	newDstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:00")
	mod := &PacketModifier{
		VLAN:    100,
		SrcMAC:  newSrcMAC,
		DstMAC:  newDstMAC,
		SrcIP:   net.ParseIP("172.16.0.100").To4(),
		DstIP:   net.ParseIP("172.16.0.200").To4(),
		SrcPort: 12345,
		DstPort: 443,
		TTL:     64,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证VLAN
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 100 {
		t.Fatalf("expected VLAN ID 100, got %d", vlan.VLANIdentifier)
	}

	// 验证MAC
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.SrcMAC.String() != "11:22:33:44:55:66" {
		t.Fatalf("expected src MAC 11:22:33:44:55:66, got %s", eth.SrcMAC.String())
	}

	// 验证IP
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "172.16.0.100" {
		t.Fatalf("expected src IP 172.16.0.100, got %s", ip4.SrcIP.String())
	}

	// 验证TCP
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if int(tcp.SrcPort) != 12345 {
		t.Fatalf("expected src port 12345, got %d", tcp.SrcPort)
	}
	if int(tcp.DstPort) != 443 {
		t.Fatalf("expected dst port 443, got %d", tcp.DstPort)
	}
}

// TestUDPPacketWithVLAN 测试带VLAN的UDP包
func TestUDPPacketWithVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// 构建不带VLAN的UDP包
	pkt := buildTestUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 5000, 53, payload)

	// 插入VLAN并修改
	mod := &PacketModifier{
		VLAN:    200,
		SrcIP:   net.ParseIP("192.168.1.10").To4(),
		DstIP:   net.ParseIP("192.168.1.20").To4(),
		SrcPort: 6000,
		DstPort: 8080,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证VLAN
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 200 {
		t.Fatalf("expected VLAN ID 200, got %d", vlan.VLANIdentifier)
	}

	// 验证IP
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "192.168.1.10" {
		t.Fatalf("expected src IP 192.168.1.10, got %s", ip4.SrcIP.String())
	}

	// 验证UDP
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if int(udp.SrcPort) != 6000 {
		t.Fatalf("expected src port 6000, got %d", udp.SrcPort)
	}
	if int(udp.DstPort) != 8080 {
		t.Fatalf("expected dst port 8080, got %d", udp.DstPort)
	}

	// 验证payload保留
	if len(udp.Payload) != 4 {
		t.Fatalf("expected payload length 4, got %d", len(udp.Payload))
	}
}

// TestTCPPacketWithoutVLAN 测试不带VLAN的TCP包
func TestTCPPacketWithoutVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	pkt := buildTestPacket(srcMAC, dstMAC, srcIP, dstIP, 8080, 80)

	mod := &PacketModifier{
		SrcIP:   net.ParseIP("172.16.0.1").To4(),
		DstIP:   net.ParseIP("172.16.0.2").To4(),
		SrcPort: 9999,
		DstPort: 443,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证没有VLAN层
	if packet.Layer(layers.LayerTypeDot1Q) != nil {
		t.Fatal("packet should not have VLAN layer")
	}

	// 验证IP
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "172.16.0.1" {
		t.Fatalf("expected src IP 172.16.0.1, got %s", ip4.SrcIP.String())
	}

	// 验证TCP
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if int(tcp.SrcPort) != 9999 {
		t.Fatalf("expected src port 9999, got %d", tcp.SrcPort)
	}
}

// TestUDPPacketWithoutVLAN 测试不带VLAN的UDP包
func TestUDPPacketWithoutVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte{0x01, 0x02}

	pkt := buildTestUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 5000, 53, payload)

	mod := &PacketModifier{
		SrcIP:   net.ParseIP("192.168.1.1").To4(),
		DstIP:   net.ParseIP("192.168.1.2").To4(),
		SrcPort: 6000,
		DstPort: 8080,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证没有VLAN层
	if packet.Layer(layers.LayerTypeDot1Q) != nil {
		t.Fatal("packet should not have VLAN layer")
	}

	// 验证UDP
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if int(udp.SrcPort) != 6000 {
		t.Fatalf("expected src port 6000, got %d", udp.SrcPort)
	}
}

// TestICMPPacketWithoutVLAN 测试不带VLAN的ICMP包
func TestICMPPacketWithoutVLAN(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte("test")

	pkt := buildTestICMPPacket(srcMAC, dstMAC, srcIP, dstIP, 8, 0, payload)

	mod := &PacketModifier{
		SrcIP: net.ParseIP("172.16.0.1").To4(),
		DstIP: net.ParseIP("172.16.0.2").To4(),
		TTL:   128,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证没有VLAN层
	if packet.Layer(layers.LayerTypeDot1Q) != nil {
		t.Fatal("packet should not have VLAN layer")
	}

	// 验证IP
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "172.16.0.1" {
		t.Fatalf("expected src IP 172.16.0.1, got %s", ip4.SrcIP.String())
	}
	if ip4.TTL != 128 {
		t.Fatalf("expected TTL 128, got %d", ip4.TTL)
	}

	// 验证ICMP
	icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.TypeCode.Type() != 8 {
		t.Fatalf("expected ICMP type 8, got %d", icmp.TypeCode.Type())
	}
}

// TestExistingVLANPacket 测试已有VLAN的包
func TestExistingVLANPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()

	// 构建带VLAN 100的TCP包
	pkt := buildTestVLANPacket(srcMAC, dstMAC, srcIP, dstIP, 8080, 80, 100)

	// 修改VLAN为200
	mod := &PacketModifier{
		VLAN: 200,
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证VLAN被修改
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 200 {
		t.Fatalf("expected VLAN ID 200, got %d", vlan.VLANIdentifier)
	}
}

// TestExistingVLANUDPPacket 测试已有VLAN的UDP包
func TestExistingVLANUDPPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte{0xAA, 0xBB}

	// 构建带VLAN 100的UDP包
	pkt := buildTestVLANUDPPacket(srcMAC, dstMAC, srcIP, dstIP, 5000, 53, 100, payload)

	// 修改VLAN和IP
	mod := &PacketModifier{
		VLAN:  300,
		SrcIP: net.ParseIP("192.168.1.1").To4(),
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证VLAN被修改
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 300 {
		t.Fatalf("expected VLAN ID 300, got %d", vlan.VLANIdentifier)
	}

	// 验证IP被修改
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.SrcIP.String() != "192.168.1.1" {
		t.Fatalf("expected src IP 192.168.1.1, got %s", ip4.SrcIP.String())
	}
}

// TestExistingVLANICMPPacket 测试已有VLAN的ICMP包
func TestExistingVLANICMPPacket(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:11:22:33:44:55")
	dstMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	srcIP := net.ParseIP("10.0.0.1").To4()
	dstIP := net.ParseIP("10.0.0.2").To4()
	payload := []byte("ping")

	// 构建带VLAN 100的ICMP包
	pkt := buildTestVLANICMPPacket(srcMAC, dstMAC, srcIP, dstIP, 8, 0, 100, payload)

	// 修改VLAN和IP
	mod := &PacketModifier{
		VLAN:  400,
		DstIP: net.ParseIP("172.16.0.1").To4(),
	}

	result, err := mod.Modify(pkt, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	packet := gopacket.NewPacket(result, layers.LayerTypeEthernet, gopacket.Default)

	// 验证VLAN被修改
	vlan := packet.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.VLANIdentifier != 400 {
		t.Fatalf("expected VLAN ID 400, got %d", vlan.VLANIdentifier)
	}

	// 验证IP被修改
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.DstIP.String() != "172.16.0.1" {
		t.Fatalf("expected dst IP 172.16.0.1, got %s", ip4.DstIP.String())
	}
}

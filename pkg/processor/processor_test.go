package processor

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"sendpcap/pkg/config"
	"sendpcap/pkg/modifier"
)

func buildTestTCPPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
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
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip4, tcp)
	return buf.Bytes()
}

func TestExtractFlowKey(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	raw := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.2").To4(),
		80, 8080)
	pkt := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)

	key, ok := extractFlowKey(pkt)
	if !ok {
		t.Fatal("expected valid flow key")
	}
	if key.SrcIP != "10.0.0.1" {
		t.Fatalf("expected SrcIP 10.0.0.1, got %s", key.SrcIP)
	}
	if key.DstIP != "10.0.0.2" {
		t.Fatalf("expected DstIP 10.0.0.2, got %s", key.DstIP)
	}
	if key.SrcPort != 80 {
		t.Fatalf("expected SrcPort 80, got %d", key.SrcPort)
	}
	if key.DstPort != 8080 {
		t.Fatalf("expected DstPort 8080, got %d", key.DstPort)
	}
	if key.Protocol != 6 {
		t.Fatalf("expected Protocol 6, got %d", key.Protocol)
	}
}

func TestGroupPacketsByFlow(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	// Build 3 packets: 2 same flow (bidirectional), 1 different flow
	// raw1: 10.0.0.1:80 → 10.0.0.2:8080 (upstream)
	// raw2: 10.0.0.2:8080 → 10.0.0.1:80 (downstream, same session)
	// raw3: 10.0.0.1:443 → 10.0.0.3:9090 (different flow)
	raw1 := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.2").To4(), 80, 8080)
	raw2 := buildTestTCPPacket(dstMAC, srcMAC,
		net.ParseIP("10.0.0.2").To4(), net.ParseIP("10.0.0.1").To4(), 8080, 80)
	raw3 := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.3").To4(), 443, 9090)

	pkts := []gopacket.Packet{
		gopacket.NewPacket(raw1, layers.LayerTypeEthernet, gopacket.Default),
		gopacket.NewPacket(raw2, layers.LayerTypeEthernet, gopacket.Default),
		gopacket.NewPacket(raw3, layers.LayerTypeEthernet, gopacket.Default),
	}

	flows := groupPacketsByFlow(pkts)
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(flows))
	}
	// flow 0: raw1 + raw2 (bidirectional, same session) = 2 packets
	if len(flows[0].Packets) != 2 {
		t.Fatalf("flow 0: expected 2 packets (bidirectional), got %d", len(flows[0].Packets))
	}
	// flow 1: raw3 = 1 packet
	if len(flows[1].Packets) != 1 {
		t.Fatalf("flow 1: expected 1 packet, got %d", len(flows[1].Packets))
	}
}

func TestProcessFileFlowBased(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	// Create temp dirs
	tempDir := t.TempDir()
	targetDir := filepath.Join(tempDir, "output")
	inputDir := filepath.Join(tempDir, "input")
	os.MkdirAll(targetDir, 0755)
	os.MkdirAll(inputDir, 0755)

	// Build pcap with 2 flows (3 packets total)
	// raw1 + raw2 = bidirectional flow 1, raw3 = flow 2
	raw1 := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.2").To4(), 80, 8080)
	raw2 := buildTestTCPPacket(dstMAC, srcMAC,
		net.ParseIP("10.0.0.2").To4(), net.ParseIP("10.0.0.1").To4(), 8080, 80)
	raw3 := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("192.168.1.1").To4(), net.ParseIP("192.168.1.2").To4(), 443, 9090)

	// Write input pcap
	inputFile := filepath.Join(inputDir, "test.pcap")
	writeRawPcap(t, inputFile, [][]byte{raw1, raw2, raw3})

	proc, err := NewProcessor(targetDir, true, true)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	defer proc.Cleanup()

	// Config with no IP/port overrides → 1 combo (default)
	cfg := &config.Config{}
	mod := &modifier.PacketModifier{}

	if err := proc.ProcessFile(inputFile, cfg, mod); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// 2 flows x 1 combo = 2 output files
	entries, _ := os.ReadDir(targetDir)
	if len(entries) != 2 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("expected 2 output files, got %d: %v", len(entries), names)
	}
}

func TestProcessFileFlowXCombo(t *testing.T) {
	srcMAC, _ := net.ParseMAC("00:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("00:00:00:00:00:02")

	tempDir := t.TempDir()
	targetDir := filepath.Join(tempDir, "output")
	inputDir := filepath.Join(tempDir, "input")
	os.MkdirAll(targetDir, 0755)
	os.MkdirAll(inputDir, 0755)

	// 2 flows
	raw1 := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.2").To4(), 80, 8080)
	raw2 := buildTestTCPPacket(srcMAC, dstMAC,
		net.ParseIP("192.168.1.1").To4(), net.ParseIP("192.168.1.2").To4(), 443, 9090)

	inputFile := filepath.Join(inputDir, "test.pcap")
	writeRawPcap(t, inputFile, [][]byte{raw1, raw2})

	proc, err := NewProcessor(targetDir, true, true)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	defer proc.Cleanup()

	// Config with 2 src IPs → 2 combos
	cfg := &config.Config{
		SrcIPStart: net.ParseIP("172.16.0.1").To4(),
		SrcIPEnd:   net.ParseIP("172.16.0.2").To4(),
	}
	mod := &modifier.PacketModifier{}

	if err := proc.ProcessFile(inputFile, cfg, mod); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// 2 flows x 2 combos = 4 output files
	entries, _ := os.ReadDir(targetDir)
	if len(entries) != 4 {
		t.Fatalf("expected 4 output files, got %d", len(entries))
	}
}

func writeRawPcap(t *testing.T, path string, packets [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &pcapWriter{f: f}
	w.writeHeader()
	for _, pkt := range packets {
		w.writePacket(pkt)
	}
}

// Minimal pcap writer for tests (avoids importing pcapgo for writing test data)
type pcapWriter struct {
	f *os.File
}

func (w *pcapWriter) writeHeader() {
	header := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, // magic
		0x02, 0x00, 0x04, 0x00, // version 2.4
		0x00, 0x00, 0x00, 0x00, // thiszone
		0x00, 0x00, 0x00, 0x00, // sigfigs
		0x00, 0x00, 0xff, 0xff, // snaplen
		0x01, 0x00, 0x00, 0x00, // network (ethernet)
	}
	w.f.Write(header)
}

func (w *pcapWriter) writePacket(data []byte) {
	pktLen := uint32(len(data))
	// packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
	header := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		byte(pktLen), byte(pktLen >> 8), byte(pktLen >> 16), byte(pktLen >> 24),
		byte(pktLen), byte(pktLen >> 8), byte(pktLen >> 16), byte(pktLen >> 24),
	}
	w.f.Write(header)
	w.f.Write(data)
}

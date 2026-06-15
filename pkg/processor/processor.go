package processor

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"sendpcap/pkg/config"
	"sendpcap/pkg/generator"
	"sendpcap/pkg/modifier"
)

// FlowKey represents a unique 5-tuple flow identifier
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// normalizeFlowKey normalizes a 5-tuple into a direction-independent key
// Smaller IP goes to SrcIP, ports follow their IPs, protocol unchanged
func normalizeFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) FlowKey {
	if srcIP < dstIP || (srcIP == dstIP && srcPort <= dstPort) {
		return FlowKey{SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Protocol: proto}
	}
	return FlowKey{SrcIP: dstIP, DstIP: srcIP, SrcPort: dstPort, DstPort: srcPort, Protocol: proto}
}

// flowEntry holds an ordered flow key, direction info, and its packets
type flowEntry struct {
	Key       FlowKey
	Packets   []gopacket.Packet
	UpSrcIP   string // original upstream src IP (for direction-aware modification)
	UpDstIP   string
	UpSrcPort uint16
	UpDstPort uint16
}

// Processor handles pcap file processing
type Processor struct {
	TargetDir string
	Quiet     bool
	NoWait    bool
	TempDir   string
}

// NewProcessor creates a new Processor
func NewProcessor(targetDir string, quiet bool, noWait bool) (*Processor, error) {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create target directory: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "sendpcap_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	return &Processor{
		TargetDir: targetDir,
		Quiet:     quiet,
		NoWait:    noWait,
		TempDir:   tempDir,
	}, nil
}

// Cleanup removes the temporary directory
func (p *Processor) Cleanup() error {
	return os.RemoveAll(p.TempDir)
}

// ProcessFile processes a single pcap file through all combinations, grouped by flow
func (p *Processor) ProcessFile(srcPath string, cfg *config.Config, mod *modifier.PacketModifier) error {
	packets, err := readAllPackets(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read pcap: %w", err)
	}

	combos, err := generator.GenerateCombinations(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate combinations: %w", err)
	}

	// Group packets by flow (5-tuple)
	flows := groupPacketsByFlow(packets)
	baseName := filepath.Base(srcPath)
	totalFiles := len(flows) * len(combos)
	fileIdx := 0

	for flowIdx, flow := range flows {
		for comboIdx, combo := range combos {
			comboMod := *mod
			if combo.SrcIP != nil {
				comboMod.SrcIP = combo.SrcIP
			}
			if combo.DstIP != nil {
				comboMod.DstIP = combo.DstIP
			}
			if combo.SrcPort > 0 {
				comboMod.SrcPort = combo.SrcPort
			}
			if combo.DstPort > 0 {
				comboMod.DstPort = combo.DstPort
			}

			tempFile := filepath.Join(p.TempDir, fmt.Sprintf("%s_flow_%d_combo_%d.pcap", baseName, flowIdx, comboIdx))
			if err := writePackets(tempFile, flow.Packets, &comboMod, flow.UpSrcIP, flow.UpDstIP, flow.UpSrcPort, flow.UpDstPort); err != nil {
				return fmt.Errorf("failed to write flow %d combo %d: %w", flowIdx, comboIdx, err)
			}

			var targetFile string
			if p.Quiet {
				targetFile = filepath.Join(p.TargetDir, fmt.Sprintf("%s_flow_%d_combo_%d.pcap", baseName, flowIdx, comboIdx))
			} else {
				targetFile = filepath.Join(p.TargetDir, fmt.Sprintf("%s_flow_%d_combo_%d.pcap.osp", baseName, flowIdx, comboIdx))
			}

			if err := copyFile(tempFile, targetFile); err != nil {
				return fmt.Errorf("failed to copy flow %d combo %d: %w", flowIdx, comboIdx, err)
			}

			fileIdx++
			fmt.Printf("[INFO] %d/%d Flow %d Combo %d: %s >> %s\n", fileIdx, totalFiles, flowIdx, comboIdx, baseName, targetFile)
			if !p.NoWait {
				waitForFileGone(targetFile)
			}
		}
	}

	return nil
}

// extractFlowKey extracts the 5-tuple flow key from a packet
func extractFlowKey(pkt gopacket.Packet) (FlowKey, bool) {
	var key FlowKey

	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return key, false
	}
	ipv4 := ipLayer.(*layers.IPv4)
	srcIP := ipv4.SrcIP.To4()
	dstIP := ipv4.DstIP.To4()
	if srcIP == nil || dstIP == nil {
		return key, false
	}
	key.SrcIP = srcIP.String()
	key.DstIP = dstIP.String()
	key.Protocol = uint8(ipv4.Protocol)

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		key.SrcPort = uint16(tcp.SrcPort)
		key.DstPort = uint16(tcp.DstPort)
		return key, true
	}
	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		key.SrcPort = uint16(udp.SrcPort)
		key.DstPort = uint16(udp.DstPort)
		return key, true
	}
	// No transport layer — use protocol only
	key.SrcPort = 0
	key.DstPort = 0
	return key, true
}

// detectFlowDirection detects the upstream direction for a flow based on the first packet.
// Returns (upstreamSrcIP, upstreamDstIP, upstreamSrcPort, upstreamDstPort).
//
// Heuristic limitations: When the first packet is not a SYN/SYN-ACK, direction is inferred
// from port numbers (larger port → smaller port = upstream). This can be wrong when the
// client uses a smaller port than the server, or when ports are equal.
func detectFlowDirection(pkt gopacket.Packet) (string, string, uint16, uint16) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return "", "", 0, 0
	}
	ipv4 := ipLayer.(*layers.IPv4)
	srcIP := ipv4.SrcIP.To4()
	dstIP := ipv4.DstIP.To4()
	if srcIP == nil || dstIP == nil {
		return "", "", 0, 0
	}

	// TCP: use SYN/SYN-ACK to determine direction
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			// SYN packet — src is upstream
			return srcIP.String(), dstIP.String(), uint16(tcp.SrcPort), uint16(tcp.DstPort)
		}
		if tcp.SYN && tcp.ACK {
			// SYN-ACK — src is downstream, dst is upstream
			return dstIP.String(), srcIP.String(), uint16(tcp.DstPort), uint16(tcp.SrcPort)
		}
		// Established connection — fall through to port-based detection
	}

	// Port-based heuristic: larger port → smaller port = upstream direction
	srcPort := uint16(0)
	dstPort := uint16(0)

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	} else {
		// No ports — assume src→dst is upstream
		return srcIP.String(), dstIP.String(), 0, 0
	}

	if srcPort >= dstPort {
		// srcPort > dstPort: larger port → smaller port = upstream
		// srcPort == dstPort: first packet direction = upstream
		return srcIP.String(), dstIP.String(), srcPort, dstPort
	}
	// dstPort > srcPort
	return dstIP.String(), srcIP.String(), dstPort, srcPort
}

// isDownstream checks if a packet is in the downstream direction given the upstream reference
func isDownstream(pkt gopacket.Packet, upSrcIP, upDstIP string, upSrcPort, upDstPort uint16) bool {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return false
	}
	ipv4 := ipLayer.(*layers.IPv4)
	pktSrcIP := ipv4.SrcIP.To4()
	pktDstIP := ipv4.DstIP.To4()
	if pktSrcIP == nil || pktDstIP == nil {
		return false
	}

	// If this packet's src match upstream src, it's upstream
	if pktSrcIP.String() == upSrcIP && pktDstIP.String() == upDstIP {
		// Check port direction for confirmation
		if upSrcPort > 0 && upDstPort > 0 {
			var pktSrcPort, pktDstPort uint16
			if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				pktSrcPort = uint16(tcpLayer.(*layers.TCP).SrcPort)
				pktDstPort = uint16(tcpLayer.(*layers.TCP).DstPort)
			} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
				pktSrcPort = uint16(udpLayer.(*layers.UDP).SrcPort)
				pktDstPort = uint16(udpLayer.(*layers.UDP).DstPort)
			}
			if pktSrcPort == upSrcPort && pktDstPort == upDstPort {
				return false // upstream
			}
			if pktSrcPort == upDstPort && pktDstPort == upSrcPort {
				return true // downstream
			}
		}
		return false
	}
	return pktSrcIP.String() == upDstIP && pktDstIP.String() == upSrcIP
}

// groupPacketsByFlow groups packets by their 5-tuple flow key, preserving order
func groupPacketsByFlow(packets []gopacket.Packet) []flowEntry {
	flowMap := make(map[FlowKey]int) // map key → index in flows slice
	var flows []flowEntry

	// Reserve index 0 for non-classifiable packets
	noFlowKey := FlowKey{SrcIP: "_no_flow_"}
	flowMap[noFlowKey] = 0
	flows = append(flows, flowEntry{Key: noFlowKey})

	for _, pkt := range packets {
		rawKey, ok := extractFlowKey(pkt)
		if !ok {
			// Non-IPv4 or no transport layer → group into no-flow
			flows[0].Packets = append(flows[0].Packets, pkt)
			continue
		}
		key := normalizeFlowKey(rawKey.SrcIP, rawKey.DstIP, rawKey.SrcPort, rawKey.DstPort, rawKey.Protocol)
		idx, exists := flowMap[key]
		if !exists {
			idx = len(flows)
			flowMap[key] = idx
			// Detect direction from first packet
			upSrcIP, upDstIP, upSrcPort, upDstPort := detectFlowDirection(pkt)
			flows = append(flows, flowEntry{
				Key:       key,
				UpSrcIP:   upSrcIP,
				UpDstIP:   upDstIP,
				UpSrcPort: upSrcPort,
				UpDstPort: upDstPort,
			})
		}
		flows[idx].Packets = append(flows[idx].Packets, pkt)
	}

	// Remove no-flow group if empty
	if len(flows[0].Packets) == 0 {
		flows = flows[1:]
	}

	return flows
}

func readAllPackets(path string) ([]gopacket.Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read magic bytes to detect format
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	switch magic {
	case 0x0a0d0d0a: // pcapng
		return readPcapngPackets(f)
	case 0xa1b2cd34: // nanosecond pcap
		return readNanoPcapPackets(f)
	default: // standard pcap (0xa1b2c3d4 or byte-swapped)
		return readStandardPcapPackets(f)
	}
}

// readStandardPcapPackets reads packets from a standard pcap file
func readStandardPcapPackets(f *os.File) ([]gopacket.Packet, error) {
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}
	linkType := reader.LinkType()

	var packets []gopacket.Packet
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		packets = append(packets, gopacket.NewPacket(data, linkType, gopacket.Default))
	}
	return packets, nil
}

// readPcapngPackets reads packets from a pcapng file.
// Uses per-interface link types from the pcapng interface description blocks.
func readPcapngPackets(f *os.File) ([]gopacket.Packet, error) {
	reader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{
		WantMixedLinkType: true,
	})
	if err != nil {
		return nil, err
	}

	var packets []gopacket.Packet
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// Determine link type from the interface that captured this packet
		linkType := layers.LinkTypeEthernet
		if iface, err := reader.Interface(ci.InterfaceIndex); err == nil {
			linkType = iface.LinkType
		}
		packets = append(packets, gopacket.NewPacket(data, linkType, gopacket.Default))
	}
	return packets, nil
}

// readNanoPcapPackets reads packets from a variant pcap file (magic 0xa1b2cd34)
// This format has 24-byte packet headers (standard 16 + 8 extra reserved bytes)
// and uses NULL (BSD loopback) link type with 4-byte family prefix before IP data
func readNanoPcapPackets(f *os.File) ([]gopacket.Packet, error) {
	// Read and validate magic
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return nil, err
	}
	if magic != 0xa1b2cd34 {
		return nil, fmt.Errorf("unexpected variant pcap magic: %x", magic)
	}

	// Read rest of global header (24 bytes total, 4 already read)
	var header struct {
		VersionMajor uint16
		VersionMinor uint16
		ThisZone     int32
		SigFigs      uint32
		SnapLen      uint32
		Network      uint32
	}
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read pcap header: %w", err)
	}

	linkType := layers.LinkType(header.Network)

	var packets []gopacket.Packet
	for {
		// Read 24-byte packet header (standard 16 + 8 extra bytes)
		var pktHeader struct {
			TsSec   uint32
			TsUsec  uint32
			InclLen uint32
			OrigLen uint32
			Extra1  uint32
			Extra2  uint32
		}
		if err := binary.Read(f, binary.LittleEndian, &pktHeader); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read packet header: %w", err)
		}

		const maxPacketSize = 262144 // 256KB, sufficient for any legitimate network packet
		if pktHeader.InclLen > maxPacketSize {
			return nil, fmt.Errorf("packet too large: %d bytes (max %d)", pktHeader.InclLen, maxPacketSize)
		}
		data := make([]byte, pktHeader.InclLen)
		if _, err := io.ReadFull(f, data); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break // truncated last packet, stop reading
			}
			return nil, fmt.Errorf("failed to read packet data: %w", err)
		}

		// For NULL (BSD loopback) link type, convert to Ethernet framing
		// NULL link has a 4-byte address family prefix, strip it and add Ethernet header
		if linkType == layers.LinkTypeNull && len(data) > 4 {
			data = convertNullToEthernet(data)
			packets = append(packets, gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default))
		} else {
			packets = append(packets, gopacket.NewPacket(data, linkType, gopacket.Default))
		}
	}

	return packets, nil
}

func writePackets(path string, packets []gopacket.Packet, mod *modifier.PacketModifier, upSrcIP, upDstIP string, upSrcPort, upDstPort uint16) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}

	for _, pkt := range packets {
		raw := pkt.Data()
		down := isDownstream(pkt, upSrcIP, upDstIP, upSrcPort, upDstPort)
		modified, err := mod.Modify(raw, down)
		if err != nil {
			return err
		}
		if modified == nil {
			continue
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(modified),
			Length:        len(modified),
		}, modified); err != nil {
			return err
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func waitForFileGone(path string) {
	// Wait up to 60 seconds for the file to be consumed
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("[WARN] File %s was not consumed within 60s, proceeding anyway\n", path)
}

// convertNullToEthernet converts a NULL/Loopback link-layer packet to Ethernet framing.
// NULL link packets have a 4-byte address family prefix followed by IP data.
// This strips the prefix and prepends a 14-byte Ethernet header.
func convertNullToEthernet(data []byte) []byte {
	ipData := data[4:] // strip 4-byte NULL family header

	// Determine Ethernet type from IP version
	var ethType uint16 = 0x0800 // IPv4
	if len(ipData) > 0 && (ipData[0]>>4) == 6 {
		ethType = 0x86DD // IPv6
	}

	ethHeader := make([]byte, 14)
	// dst MAC: 00:00:00:00:00:00 (placeholder)
	// src MAC: 00:00:00:00:00:00 (placeholder)
	ethHeader[12] = byte(ethType >> 8)
	ethHeader[13] = byte(ethType)

	result := make([]byte, 14+len(ipData))
	copy(result, ethHeader)
	copy(result[14:], ipData)
	return result
}

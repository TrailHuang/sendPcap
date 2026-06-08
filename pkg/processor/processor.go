package processor

import (
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

// Processor handles pcap file processing
type Processor struct {
	TargetDir string
	Quiet     bool
	TempDir   string
}

// NewProcessor creates a new Processor
func NewProcessor(targetDir string, quiet bool) (*Processor, error) {
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
		TempDir:   tempDir,
	}, nil
}

// Cleanup removes the temporary directory
func (p *Processor) Cleanup() error {
	return os.RemoveAll(p.TempDir)
}

// ProcessFile processes a single pcap file through all combinations
func (p *Processor) ProcessFile(srcPath string, cfg *config.Config, mod *modifier.PacketModifier) error {
	packets, err := readAllPackets(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read pcap: %w", err)
	}

	combos, err := generator.GenerateCombinations(cfg)
	if err != nil {
		return fmt.Errorf("failed to generate combinations: %w", err)
	}

	baseName := filepath.Base(srcPath)

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

		tempFile := filepath.Join(p.TempDir, fmt.Sprintf("%s_combo_%d.pcap", baseName, comboIdx))
		if err := writePackets(tempFile, packets, &comboMod); err != nil {
			return fmt.Errorf("failed to write combo %d: %w", comboIdx, err)
		}

		var targetFile string
		if p.Quiet {
			targetFile = filepath.Join(p.TargetDir, fmt.Sprintf("%s_combo_%d.pcap", baseName, comboIdx))
		} else {
			targetFile = filepath.Join(p.TargetDir, fmt.Sprintf("%s_combo_%d.pcap.osp", baseName, comboIdx))
		}

		if err := copyFile(tempFile, targetFile); err != nil {
			return fmt.Errorf("failed to copy combo %d: %w", comboIdx, err)
		}

		waitForFileGone(targetFile)

		fmt.Printf("[INFO] Combo %d/%d: %s >> %s\n", comboIdx+1, len(combos), baseName, targetFile)
	}

	return nil
}

func readAllPackets(path string) ([]gopacket.Packet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}

	var packets []gopacket.Packet
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		packets = append(packets, gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default))
	}

	return packets, nil
}

func writePackets(path string, packets []gopacket.Packet, mod *modifier.PacketModifier) error {
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
		modified, err := mod.Modify(raw)
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
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

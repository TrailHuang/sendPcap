# SendPcap Go 程序 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 Go 语言实现 pcap 文件回放工具，支持报文修改（MAC、VLAN、IP、端口、TTL、Protocol）和 IP/端口范围组合生成。

**Architecture:** 流式处理架构 — 读取原始 pcap → 逐包修改 → 写出临时 pcap → 复制到目标目录 → 清理临时文件。模块化设计：配置层、修改器层、组合生成器、处理器层。

**Tech Stack:** Go 1.21+, gopacket/pcapgo, gopacket/layers, yaml.v3, spf13/pflag

---

## File Structure

```
sendPcap/
├── cmd/
│   └── main.go                  # 入口：参数解析、配置合并、调度执行
├── pkg/
│   ├── config/
│   │   └── config.go            # 配置结构体、CLI 解析、YAML 加载、校验
│   ├── modifier/
│   │   └── modifier.go          # PacketModifier：报文修改核心逻辑
│   ├── generator/
│   │   └── generator.go         # 组合生成器：IP/端口范围展开
│   ├── processor/
│   │   └── processor.go         # pcap 文件处理：读取、修改、写出、复制
│   └── util/
│       └── util.go              # 工具函数：MAC/IP 解析、文件轮询、目录遍历
├── go.mod
└── go.sum
```

---

### Task 1: 初始化 Go 项目

**Files:**
- Create: `go.mod`

- [ ] **Step 1: 创建 go.mod**

在项目根目录执行：

```bash
cd /mnt/d/BaiduSyncdisk/my_code/GO/sendPcap
go mod init sendpcap
go get github.com/google/gopacket
go get gopkg.in/yaml.v3
go get github.com/spf13/pflag
```

- [ ] **Step 2: 验证依赖安装**

```bash
go mod tidy
```

Expected: 无错误输出

- [ ] **Step 3: 创建目录结构**

```bash
mkdir -p cmd pkg/config pkg/modifier pkg/generator pkg/processor pkg/util
```

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "feat: initialize go module with dependencies"
```

---

### Task 2: 配置模块 (pkg/config/config.go)

**Files:**
- Create: `pkg/config/config.go`

- [ ] **Step 1: 编写测试**

```go
// pkg/config/config_test.go
package config

import "testing"

func TestParseMAC(t *testing.T) {
    mac, err := ParseMAC("00:11:22:33:44:55")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if mac.String() != "00:11:22:33:44:55" {
        t.Fatalf("expected 00:11:22:33:44:55, got %s", mac.String())
    }
}

func TestParseMACInvalid(t *testing.T) {
    _, err := ParseMAC("invalid")
    if err == nil {
        t.Fatal("expected error for invalid MAC")
    }
}

func TestIPToUint32(t *testing.T) {
    ip := ParseIP("192.168.1.1")
    if ip == nil {
        t.Fatal("expected valid IP")
    }
    val := IPToUint32(ip)
    if val != 0xc0a80101 {
        t.Fatalf("expected 0xc0a80101, got 0x%x", val)
    }
}

func TestUint32ToIP(t *testing.T) {
    ip := Uint32ToIP(0xc0a80101)
    if ip.String() != "192.168.1.1" {
        t.Fatalf("expected 192.168.1.1, got %s", ip.String())
    }
}

func TestConfigValidate(t *testing.T) {
    c := &Config{}
    if err := c.Validate(); err != nil {
        t.Fatalf("empty config should be valid: %v", err)
    }
}

func TestConfigValidateIPRange(t *testing.T) {
    c := &Config{
        SrcIPStart: ParseIP("10.0.0.10"),
        SrcIPEnd:   ParseIP("10.0.0.1"),
    }
    if err := c.Validate(); err == nil {
        t.Fatal("expected error for invalid IP range")
    }
}

func TestConfigValidatePortRange(t *testing.T) {
    c := &Config{
        SrcPortStart: 100,
        SrcPortEnd:   50,
    }
    if err := c.Validate(); err == nil {
        t.Fatal("expected error for invalid port range")
    }
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
go test ./pkg/config/ -v
```

Expected: FAIL — 文件不存在或函数未定义

- [ ] **Step 3: 编写实现**

```go
// pkg/config/config.go
package config

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// Config holds all modification rules for pcap packets
type Config struct {
	SrcMAC       net.HardwareAddr `yaml:"src_mac"`
	DstMAC       net.HardwareAddr `yaml:"dst_mac"`
	VLAN         int              `yaml:"vlan"`
	SrcIP        net.IP           `yaml:"src_ip"`
	DstIP        net.IP           `yaml:"dst_ip"`
	SrcIPStart   net.IP           `yaml:"src_ip_start"`
	SrcIPEnd     net.IP           `yaml:"src_ip_end"`
	DstIPStart   net.IP           `yaml:"dst_ip_start"`
	DstIPEnd     net.IP           `yaml:"dst_ip_end"`
	SrcPort      int              `yaml:"src_port"`
	DstPort      int              `yaml:"dst_port"`
	SrcPortStart int              `yaml:"src_port_start"`
	SrcPortEnd   int              `yaml:"src_port_end"`
	DstPortStart int              `yaml:"dst_port_start"`
	DstPortEnd   int              `yaml:"dst_port_end"`
	TTL          int              `yaml:"ttl"`
	Protocol     int              `yaml:"protocol"`
}

// ParseMAC parses a MAC address string
func ParseMAC(s string) (net.HardwareAddr, error) {
	if s == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", s, err)
	}
	return mac, nil
}

// ParseIP parses an IPv4 address string
func ParseIP(s string) net.IP {
	if s == "" {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// IPToUint32 converts a 4-byte IP to uint32
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// Uint32ToIP converts a uint32 to net.IP
func Uint32ToIP(val uint32) net.IP {
	return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
}

// Validate checks config consistency
func (c *Config) Validate() error {
	if c.SrcIPStart != nil && c.SrcIPEnd != nil {
		if IPToUint32(c.SrcIPStart) > IPToUint32(c.SrcIPEnd) {
			return fmt.Errorf("src_ip_start (%s) > src_ip_end (%s)", c.SrcIPStart, c.SrcIPEnd)
		}
	}
	if c.DstIPStart != nil && c.DstIPEnd != nil {
		if IPToUint32(c.DstIPStart) > IPToUint32(c.DstIPEnd) {
			return fmt.Errorf("dst_ip_start (%s) > dst_ip_end (%s)", c.DstIPStart, c.DstIPEnd)
		}
	}
	if c.SrcPortStart > 0 && c.SrcPortEnd > 0 && c.SrcPortStart > c.SrcPortEnd {
		return fmt.Errorf("src_port_start (%d) > src_port_end (%d)", c.SrcPortStart, c.SrcPortEnd)
	}
	if c.DstPortStart > 0 && c.DstPortEnd > 0 && c.DstPortStart > c.DstPortEnd {
		return fmt.Errorf("dst_port_start (%d) > dst_port_end (%d)", c.DstPortStart, c.DstPortEnd)
	}
	return nil
}

// LoadConfig loads config from YAML file and CLI flags, CLI overrides file
func LoadConfig(configPath string) (*Config, error) {
	cfg := &Config{}

	// Load from YAML file if provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Parse CLI flags (override YAML values)
	fs := pflag.NewFlagSet("sendpcap", pflag.ContinueOnError)
	fs.String("src-mac", "", "Source MAC address")
	fs.String("dst-mac", "", "Destination MAC address")
	fs.Int("vlan", 0, "VLAN ID")
	fs.String("src-ip", "", "Source IP")
	fs.String("dst-ip", "", "Destination IP")
	fs.String("src-ip-start", "", "Source IP start")
	fs.String("src-ip-end", "", "Source IP end")
	fs.String("dst-ip-start", "", "Destination IP start")
	fs.String("dst-ip-end", "", "Destination IP end")
	fs.Int("src-port", 0, "Source port")
	fs.Int("dst-port", 0, "Destination port")
	fs.Int("src-port-start", 0, "Source port start")
	fs.Int("src-port-end", 0, "Source port end")
	fs.Int("dst-port-start", 0, "Destination port start")
	fs.Int("dst-port-end", 0, "Destination port end")
	fs.Int("ttl", 0, "TTL")
	fs.Int("protocol", 0, "IP protocol number")

	// Only parse if there are args to parse
	if len(os.Args) > 1 {
		_ = fs.Parse(os.Args[1:])
	}

	// CLI overrides
	if v, _ := fs.GetString("src-mac"); v != "" {
		if mac, err := ParseMAC(v); err == nil {
			cfg.SrcMAC = mac
		}
	}
	if v, _ := fs.GetString("dst-mac"); v != "" {
		if mac, err := ParseMAC(v); err == nil {
			cfg.DstMAC = mac
		}
	}
	if v, _ := fs.GetInt("vlan"); v != 0 {
		cfg.VLAN = v
	}
	if v, _ := fs.GetString("src-ip"); v != "" {
		cfg.SrcIP = ParseIP(v)
	}
	if v, _ := fs.GetString("dst-ip"); v != "" {
		cfg.DstIP = ParseIP(v)
	}
	if v, _ := fs.GetString("src-ip-start"); v != "" {
		cfg.SrcIPStart = ParseIP(v)
	}
	if v, _ := fs.GetString("src-ip-end"); v != "" {
		cfg.SrcIPEnd = ParseIP(v)
	}
	if v, _ := fs.GetString("dst-ip-start"); v != "" {
		cfg.DstIPStart = ParseIP(v)
	}
	if v, _ := fs.GetString("dst-ip-end"); v != "" {
		cfg.DstIPEnd = ParseIP(v)
	}
	if v, _ := fs.GetInt("src-port"); v != 0 {
		cfg.SrcPort = v
	}
	if v, _ := fs.GetInt("dst-port"); v != 0 {
		cfg.DstPort = v
	}
	if v, _ := fs.GetInt("src-port-start"); v != 0 {
		cfg.SrcPortStart = v
	}
	if v, _ := fs.GetInt("src-port-end"); v != 0 {
		cfg.SrcPortEnd = v
	}
	if v, _ := fs.GetInt("dst-port-start"); v != 0 {
		cfg.DstPortStart = v
	}
	if v, _ := fs.GetInt("dst-port-end"); v != 0 {
		cfg.DstPortEnd = v
	}
	if v, _ := fs.GetInt("ttl"); v != 0 {
		cfg.TTL = v
	}
	if v, _ := fs.GetInt("protocol"); v != 0 {
		cfg.Protocol = v
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
```

- [ ] **Step 4: 运行测试验证通过**

```bash
go test ./pkg/config/ -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/config/
git commit -m "feat: add config module with CLI/YAML loading and validation"
```

---

### Task 3: 报文修改器模块 (pkg/modifier/modifier.go)

**Files:**
- Create: `pkg/modifier/modifier.go`
- Create: `pkg/modifier/modifier_test.go`

- [ ] **Step 1: 编写测试**

```go
// pkg/modifier/modifier_test.go
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
```

- [ ] **Step 2: 运行测试验证失败**

```bash
go test ./pkg/modifier/ -v
```

Expected: FAIL — 文件不存在或函数未定义

- [ ] **Step 3: 编写实现**

```go
// pkg/modifier/modifier.go
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

		var networkLayer gopacket.NetworkLayer
		if ip4Layer != nil {
			networkLayer = ip4Layer
		}

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
```

- [ ] **Step 4: 运行测试验证通过**

```bash
go test ./pkg/modifier/ -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/modifier/
git commit -m "feat: add packet modifier module with MAC/IP/Port/TTL/VLAN support"
```

---

### Task 4: 组合生成器模块 (pkg/generator/generator.go)

**Files:**
- Create: `pkg/generator/generator.go`
- Create: `pkg/generator/generator_test.go`

- [ ] **Step 1: 编写测试**

```go
// pkg/generator/generator_test.go
package generator

import (
	"net"
	"testing"

	"sendpcap/pkg/config"
)

func TestGenerateCombinationsNoRange(t *testing.T) {
	cfg := &config.Config{}
	combos, err := GenerateCombinations(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(combos) != 1 {
		t.Fatalf("expected 1 combination, got %d", len(combos))
	}
}

func TestGenerateCombinationsIPRange(t *testing.T) {
	cfg := &config.Config{
		SrcIPStart: config.ParseIP("10.0.0.1"),
		SrcIPEnd:   config.ParseIP("10.0.0.3"),
	}
	combos, err := GenerateCombinations(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(combos) != 3 {
		t.Fatalf("expected 3 combinations, got %d", len(combos))
	}
	expected := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, c := range combos {
		if c.SrcIP.String() != expected[i] {
			t.Fatalf("combo %d: expected src IP %s, got %s", i, expected[i], c.SrcIP.String())
		}
	}
}

func TestGenerateCombinationsPortRange(t *testing.T) {
	cfg := &config.Config{
		DstPortStart: 80,
		DstPortEnd:   82,
	}
	combos, err := GenerateCombinations(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(combos) != 3 {
		t.Fatalf("expected 3 combinations, got %d", len(combos))
	}
	expected := []int{80, 81, 82}
	for i, c := range combos {
		if c.DstPort != expected[i] {
			t.Fatalf("combo %d: expected dst port %d, got %d", i, expected[i], c.DstPort)
		}
	}
}

func TestGenerateCombinationsCrossProduct(t *testing.T) {
	cfg := &config.Config{
		SrcIPStart:   config.ParseIP("10.0.0.1"),
		SrcIPEnd:     config.ParseIP("10.0.0.2"),
		DstPortStart: 80,
		DstPortEnd:   81,
	}
	combos, err := GenerateCombinations(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 2 IPs x 2 ports = 4 combinations
	if len(combos) != 4 {
		t.Fatalf("expected 4 combinations, got %d", len(combos))
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

```bash
go test ./pkg/generator/ -v
```

Expected: FAIL

- [ ] **Step 3: 编写实现**

```go
// pkg/generator/generator.go
package generator

import (
	"fmt"
	"net"

	"sendpcap/pkg/config"
)

// Combination represents a unique IP/Port combination for packet generation
type Combination struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort int
	DstPort int
}

// GenerateCombinations expands config ranges into all IP/Port combinations
func GenerateCombinations(cfg *config.Config) ([]Combination, error) {
	srcIPs := expandIPRange(cfg.SrcIP, cfg.SrcIPStart, cfg.SrcIPEnd)
	dstIPs := expandIPRange(cfg.DstIP, cfg.DstIPStart, cfg.DstIPEnd)
	srcPorts := expandPortRange(cfg.SrcPort, cfg.SrcPortStart, cfg.SrcPortEnd)
	dstPorts := expandPortRange(cfg.DstPort, cfg.DstPortStart, cfg.DstPortEnd)

	total := len(srcIPs) * len(dstIPs) * len(srcPorts) * len(dstPorts)
	if total > 10000 {
		fmt.Printf("[WARN] Large combination count: %d packets will be generated\n", total)
	}

	combos := make([]Combination, 0, total)
	for _, srcIP := range srcIPs {
		for _, dstIP := range dstIPs {
			for _, srcPort := range srcPorts {
				for _, dstPort := range dstPorts {
					c := Combination{
						SrcPort: srcPort,
						DstPort: dstPort,
					}
					if srcIP != nil {
						c.SrcIP = srcIP.To4()
					}
					if dstIP != nil {
						c.DstIP = dstIP.To4()
					}
					combos = append(combos, c)
				}
			}
		}
	}

	return combos, nil
}

func expandIPRange(single net.IP, start net.IP, end net.IP) []net.IP {
	if start != nil && end != nil {
		startVal := config.IPToUint32(start)
		endVal := config.IPToUint32(end)
		var ips []net.IP
		for v := startVal; v <= endVal; v++ {
			ips = append(ips, config.Uint32ToIP(v))
		}
		return ips
	}
	if single != nil {
		return []net.IP{single}
	}
	return []net.IP{nil} // placeholder meaning "don't modify"
}

func expandPortRange(single int, start int, end int) []int {
	if start > 0 && end > 0 {
		var ports []int
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
		return ports
	}
	if single > 0 {
		return []int{single}
	}
	return []int{0} // placeholder meaning "don't modify"
}
```

- [ ] **Step 4: 运行测试验证通过**

```bash
go test ./pkg/generator/ -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/generator/
git commit -m "feat: add combination generator for IP/Port range expansion"
```

---

### Task 5: pcap 处理器模块 (pkg/processor/processor.go)

**Files:**
- Create: `pkg/processor/processor.go`

- [ ] **Step 1: 编写实现**

```go
// pkg/processor/processor.go
package processor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"sendpcap/pkg/generator"
	"sendpcap/pkg/modifier"
)

// ProcessFile reads a pcap file, applies modifications for each combination,
// writes temporary pcap files, copies them to target directory, and cleans up.
func ProcessFile(srcPath, targetDir string, cfg interface{}, quiet bool, replayCount int, mod *modifier.PacketModifier) error {
	// Read all packets from source file as templates
	packets, info, err := readAllPackets(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read pcap: %w", err)
	}

	// Generate combinations
	combos, err := generator.GenerateCombinations(cfg.(*config.Config))
	if err != nil {
		return fmt.Errorf("failed to generate combinations: %w", err)
	}

	baseName := filepath.Base(srcPath)

	for comboIdx, combo := range combos {
		// Create a modifier copy with combination-specific IP/Port values
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

		// Create temp pcap file
		tempFile := filepath.Join(tempDir, fmt.Sprintf("%s_combo_%d.pcap", baseName, comboIdx))
		if err := writePackets(tempFile, packets, &comboMod, info); err != nil {
			return fmt.Errorf("failed to write combo %d: %w", comboIdx, err)
		}

		// Determine target filename
		var targetFile string
		if quiet {
			targetFile = filepath.Join(targetDir, fmt.Sprintf("%s_combo_%d.pcap", baseName, comboIdx))
		} else {
			targetFile = filepath.Join(targetDir, fmt.Sprintf("%s_combo_%d.pcap.osp", baseName, comboIdx))
		}

		// Copy to target directory
		if err := copyFile(tempFile, targetFile); err != nil {
			return fmt.Errorf("failed to copy combo %d: %w", comboIdx, err)
		}

		// Wait for target file to be consumed
		waitForFileGone(targetFile)

		fmt.Printf("[INFO] Combo %d/%d: %s >> %s\n", comboIdx+1, len(combos), baseName, targetFile)
	}

	return nil
}

func readAllPackets(path string) ([]gopacket.Packet, *pcapgo.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, nil, err
	}

	var packets []gopacket.Packet
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		_ = ci // capture info for timing if needed
		packets = append(packets, packet)
	}

	return packets, reader, nil
}

func writePackets(path string, packets []gopacket.Packet, mod *modifier.PacketModifier, reader *pcapgo.Reader) error {
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
			continue // skip unsupported packets
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  len(modified),
			Length:         len(modified),
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
```

Note: This file imports `config` and `layers` packages. The `config` import needs to be added, and `tempDir` variable needs to be managed. Let me fix the imports and add temp directory management.

Actually, let me restructure - the temp directory management should be handled at a higher level. Let me revise:

```go
// pkg/processor/processor.go
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
```

- [ ] **Step 2: 编译验证**

```bash
go build ./pkg/processor/
```

Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add pkg/processor/
git commit -m "feat: add pcap processor with stream read/modify/write and temp file management"
```

---

### Task 6: 工具函数模块 (pkg/util/util.go)

**Files:**
- Create: `pkg/util/util.go`

- [ ] **Step 1: 编写实现**

```go
// pkg/util/util.go
package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// CollectInputFiles collects all pcap files from a file or directory
func CollectInputFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", input, err)
	}

	if info.IsDir() {
		return collectFromDirectory(input, true)
	}

	ext := filepath.Ext(input)
	switch ext {
	case ".pcap", ".cap", ".pcapng":
		return []string{input}, nil
	default:
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}
}

// collectFromDirectory recursively finds all pcap/cap/pcapng files
func collectFromDirectory(dir string, recursive bool) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != dir && !recursive {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".pcap" || ext == ".cap" || ext == ".pcapng" {
				files = append(files, path)
			}
		}
		return nil
	})

	return files, err
}
```

- [ ] **Step 2: 编译验证**

```bash
go build ./pkg/util/
```

Expected: 无错误

- [ ] **Step 3: Commit**

```bash
git add pkg/util/
git commit -m "feat: add utility functions for file collection"
```

---

### Task 7: 主程序入口 (cmd/main.go)

**Files:**
- Create: `cmd/main.go`

- [ ] **Step 1: 编写实现**

```go
// cmd/main.go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"sendpcap/pkg/config"
	"sendpcap/pkg/modifier"
	"sendpcap/pkg/processor"
	"sendpcap/pkg/util"
)

func main() {
	// Parse common flags
	configPath := pflag.StringP("config", "c", "", "Config file path (YAML)")
	quiet := pflag.BoolP("quiet", "q", false, "Quiet mode (no .osp suffix)")
	pflag.Parse()

	args := pflag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-q] [-c config] <file_or_directory> <target_directory> [replay_count]\n", os.Args[0])
		os.Exit(1)
	}

	input := args[0]
	targetDir := "/home/updpi/pcap_dir"
	replayCount := 1

	if len(args) >= 2 {
		targetDir = args[1]
	}
	if len(args) >= 3 {
		fmt.Sscanf(args[2], "%d", &replayCount)
	}

	// Load and merge config
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Collect input files
	files, err := util.CollectInputFiles(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting files: %v\n", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "No pcap files found in %s\n", input)
		os.Exit(1)
	}

	// Create modifier from config
	mod := &modifier.PacketModifier{
		SrcMAC:   cfg.SrcMAC,
		DstMAC:   cfg.DstMAC,
		VLAN:     cfg.VLAN,
		SrcIP:    cfg.SrcIP,
		DstIP:    cfg.DstIP,
		SrcPort:  cfg.SrcPort,
		DstPort:  cfg.DstPort,
		TTL:      cfg.TTL,
		Protocol: cfg.Protocol,
	}

	// Create processor
	proc, err := processor.NewProcessor(targetDir, *quiet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating processor: %v\n", err)
		os.Exit(1)
	}
	defer proc.Cleanup()

	// Replay loop
	count := 0
	if replayCount == 0 {
		// Infinite loop
		for {
			if err := processAll(files, cfg, mod, proc); err != nil {
				fmt.Fprintf(os.Stderr, "Error processing: %v\n", err)
			}
			count++
			fmt.Printf("[%d] %s >> %s\n", count, input, targetDir)
			time.Sleep(10 * time.Second)
		}
	} else {
		for i := 0; i < replayCount; i++ {
			if err := processAll(files, cfg, mod, proc); err != nil {
				fmt.Fprintf(os.Stderr, "Error processing: %v\n", err)
				os.Exit(1)
			}
		}
	}
}

func processAll(files []string, cfg *config.Config, mod *modifier.PacketModifier, proc *processor.Processor) error {
	for _, f := range files {
		if err := proc.ProcessFile(f, cfg, mod); err != nil {
			return fmt.Errorf("failed to process %s: %w", f, err)
		}
	}
	return nil
}
```

- [ ] **Step 2: 编译验证**

```bash
go build -o sendpcap ./cmd/
```

Expected: 生成 `sendpcap` 可执行文件，无错误

- [ ] **Step 3: Commit**

```bash
git add cmd/main.go
git commit -m "feat: add main entry point with CLI parsing and replay loop"
```

---

### Task 8: 端到端测试与验证

- [ ] **Step 1: 创建测试用 pcap 文件**

使用 `tcpdump` 或 `scapy` 创建一个简单的测试 pcap：

```bash
# 如果有 tcpdump:
tcpdump -w /tmp/test.pcap -c 5 any port 80 &
curl -s http://example.com > /dev/null 2>&1
# 或者用 Python scapy:
python3 -c "
from scapy.all import *
pkt = Ether()/IP(src='10.0.0.1',dst='10.0.0.2')/TCP(sport=12345,dport=80)/Raw(b'hello')
wrpcap('/tmp/test.pcap', pkt)
"
```

- [ ] **Step 2: 基础功能测试 — 单文件无修改**

```bash
./sendpcap /tmp/test.pcap /tmp/output -q
ls /tmp/output/
```

Expected: 输出目录包含处理后的 pcap 文件

- [ ] **Step 3: MAC 修改测试**

```bash
./sendpcap --src-mac aa:bb:cc:dd:ee:ff --dst-mac 11:22:33:44:55:66 /tmp/test.pcap /tmp/output_mac -q
```

用 tcpdump 验证输出文件的 MAC 地址：

```bash
tcpdump -r /tmp/output_mac/test.pcap_combo_0.pcap -e -nn
```

Expected: 源/目的 MAC 已修改

- [ ] **Step 4: IP 范围测试**

```bash
./sendpcap --src-ip-start 10.0.0.1 --src-ip-end 10.0.0.3 /tmp/test.pcap /tmp/output_range -q
ls /tmp/output_range/
```

Expected: 生成 3 个组合文件

- [ ] **Step 5: 配置文件测试**

创建 `test_config.yaml`:

```yaml
src_mac: "aa:bb:cc:dd:ee:ff"
vlan: 100
src_ip_start: "10.0.0.1"
src_ip_end: "10.0.0.2"
dst_port_start: 80
dst_port_end: 81
```

```bash
./sendpcap -c test_config.yaml /tmp/test.pcap /tmp/output_config -q
```

Expected: 生成 4 个组合文件（2 IPs x 2 ports），带 VLAN 标签

- [ ] **Step 6: 清理测试文件**

```bash
rm -rf /tmp/test.pcap /tmp/output* test_config.yaml
```

- [ ] **Step 7: 最终 Commit**

```bash
git add -A
git commit -m "test: verify end-to-end functionality"
```

---

## Self-Review

### 1. Spec Coverage Check

| Spec Requirement | Task |
|-----------------|------|
| CLI + YAML config merge | Task 2 |
| MAC modification | Task 3, 7 |
| VLAN insertion | Task 3 |
| IP modification (single + range) | Task 3, 4, 5, 7 |
| Port modification (single + range) | Task 3, 4, 5, 7 |
| TTL/Protocol modification | Task 3 |
| Recursive directory traversal | Task 6 |
| Temp file management + cleanup | Task 5 |
| File consumption wait (polling) | Task 5 |
| Replay count (0 = infinite) | Task 7 |
| Quiet mode | Task 5, 7 |
| Auto-create target directory | Task 5 |
| Combination count warning >10000 | Task 4 |

All requirements covered.

### 2. Placeholder Scan

No TBD/TODO/fill-in-later patterns found. All code blocks contain complete implementations.

### 3. Type Consistency

- `config.Config` fields match between Task 2 (definition) and Task 5/7 (usage)
- `modifier.PacketModifier` fields match between Task 3 (definition) and Task 5/7 (usage)
- `generator.Combination` struct matches between Task 4 (definition) and Task 5 (usage)
- `processor.Processor` methods match between Task 5 (definition) and Task 7 (usage)
- All imports use `sendpcap/pkg/...` path consistently

### 4. Scope Check

Plan is focused on a single deliverable: the sendpcap binary. 8 tasks, each producing independently testable code.

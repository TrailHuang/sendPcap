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
func ParseIP(s string) (net.IP, error) {
	if s == "" {
		return nil, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q", s)
	}
	return ip.To4(), nil
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

// RegisterFlags registers all modification flags on the given FlagSet
func RegisterFlags(fs *pflag.FlagSet) {
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
}

// LoadConfig loads config from YAML file and applies CLI overrides
func LoadConfig(configPath string, fs *pflag.FlagSet) (*Config, error) {
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

	// CLI overrides
	if v, _ := fs.GetString("src-mac"); v != "" {
		mac, err := ParseMAC(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --src-mac: %w", err)
		}
		cfg.SrcMAC = mac
	}
	if v, _ := fs.GetString("dst-mac"); v != "" {
		mac, err := ParseMAC(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --dst-mac: %w", err)
		}
		cfg.DstMAC = mac
	}
	if v, _ := fs.GetInt("vlan"); v != 0 {
		cfg.VLAN = v
	}
	if v, _ := fs.GetString("src-ip"); v != "" {
		ip, err := ParseIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --src-ip: %w", err)
		}
		cfg.SrcIP = ip
	}
	if v, _ := fs.GetString("dst-ip"); v != "" {
		ip, err := ParseIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --dst-ip: %w", err)
		}
		cfg.DstIP = ip
	}
	if v, _ := fs.GetString("src-ip-start"); v != "" {
		ip, err := ParseIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --src-ip-start: %w", err)
		}
		cfg.SrcIPStart = ip
	}
	if v, _ := fs.GetString("src-ip-end"); v != "" {
		ip, err := ParseIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --src-ip-end: %w", err)
		}
		cfg.SrcIPEnd = ip
	}
	if v, _ := fs.GetString("dst-ip-start"); v != "" {
		ip, err := ParseIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --dst-ip-start: %w", err)
		}
		cfg.DstIPStart = ip
	}
	if v, _ := fs.GetString("dst-ip-end"); v != "" {
		ip, err := ParseIP(v)
		if err != nil {
			return nil, fmt.Errorf("invalid --dst-ip-end: %w", err)
		}
		cfg.DstIPEnd = ip
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

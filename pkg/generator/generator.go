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
		for v := startVal; ; v++ {
			ips = append(ips, config.Uint32ToIP(v))
			if v == endVal {
				break
			}
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

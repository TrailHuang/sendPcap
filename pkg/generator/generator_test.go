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

func mustParseIP(s string) net.IP {
	ip, err := config.ParseIP(s)
	if err != nil {
		panic(err)
	}
	return ip
}

func TestGenerateCombinationsIPRange(t *testing.T) {
	cfg := &config.Config{
		SrcIPStart: mustParseIP("10.0.0.1"),
		SrcIPEnd:   mustParseIP("10.0.0.3"),
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
		SrcIPStart:   mustParseIP("10.0.0.1"),
		SrcIPEnd:     mustParseIP("10.0.0.2"),
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

func TestGenerateCombinationsSingleIP(t *testing.T) {
	cfg := &config.Config{
		SrcIP: mustParseIP("10.0.0.5"),
	}
	combos, err := GenerateCombinations(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(combos) != 1 {
		t.Fatalf("expected 1 combination, got %d", len(combos))
	}
	if combos[0].SrcIP.String() != "10.0.0.5" {
		t.Fatalf("expected src IP 10.0.0.5, got %s", combos[0].SrcIP.String())
	}
}

func TestGenerateCombinationsSinglePort(t *testing.T) {
	cfg := &config.Config{
		SrcPort: 8080,
	}
	combos, err := GenerateCombinations(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(combos) != 1 {
		t.Fatalf("expected 1 combination, got %d", len(combos))
	}
	if combos[0].SrcPort != 8080 {
		t.Fatalf("expected src port 8080, got %d", combos[0].SrcPort)
	}
}

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

func TestParseMACEmpty(t *testing.T) {
	mac, err := ParseMAC("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mac != nil {
		t.Fatal("expected nil for empty MAC")
	}
}

func TestIPToUint32(t *testing.T) {
	ip, _ := ParseIP("192.168.1.1")
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

func TestParseIPEmpty(t *testing.T) {
	ip, err := ParseIP("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != nil {
		t.Fatal("expected nil for empty IP")
	}
}

func TestParseIPInvalid(t *testing.T) {
	_, err := ParseIP("not_an_ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestConfigValidate(t *testing.T) {
	c := &Config{}
	if err := c.Validate(); err != nil {
		t.Fatalf("empty config should be valid: %v", err)
	}
}

func TestConfigValidateIPRange(t *testing.T) {
	srcStart, _ := ParseIP("10.0.0.10")
	srcEnd, _ := ParseIP("10.0.0.1")
	c := &Config{
		SrcIPStart: srcStart,
		SrcIPEnd:   srcEnd,
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

func TestConfigValidatePortUpperBound(t *testing.T) {
	c := &Config{
		SrcPortEnd: 70000,
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for port exceeding 65535")
	}
}

func TestConfigValidatePortUpperBoundDst(t *testing.T) {
	c := &Config{
		DstPort: 65536,
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for dst_port exceeding 65535")
	}
}

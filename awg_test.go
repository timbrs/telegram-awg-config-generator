package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestParseClientsTable(t *testing.T) {
	raw := `[
  {
    "clientId": "abc123pubkey=",
    "userData": {
      "allowedIps": "10.8.1.2/32",
      "clientName": "phone",
      "creationDate": "Sun Mar 1 15:55:37 2026",
      "dataReceived": "1.59 GiB",
      "dataSent": "686.29 MiB",
      "latestHandshake": "6h, 16m, 31s ago"
    }
  },
  {
    "clientId": "def456pubkey=",
    "userData": {
      "allowedIps": "10.8.1.3/32",
      "clientName": "laptop",
      "creationDate": "Mon Mar 2 10:00:00 2026",
      "dataReceived": "500 MiB",
      "dataSent": "200 MiB",
      "latestHandshake": "1m ago"
    }
  }
]`

	var entries []ClientEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].UserData.ClientName != "phone" {
		t.Errorf("expected 'phone', got '%s'", entries[0].UserData.ClientName)
	}
	if entries[1].UserData.AllowedIPs != "10.8.1.3/32" {
		t.Errorf("expected '10.8.1.3/32', got '%s'", entries[1].UserData.AllowedIPs)
	}
}

func TestAllocateIP(t *testing.T) {
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.1.2/32"}},
		{UserData: ClientData{AllowedIPs: "10.8.1.3/32"}},
	}

	// Без srvParams — запасной режим /22, первый свободный 10.8.0.2.
	ip, err := allocateIP(nil, clients)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.0.2" {
		t.Errorf("expected 10.8.0.2, got %s", ip)
	}
}

func TestAllocateIPEmpty(t *testing.T) {
	ip, err := allocateIP(nil, nil)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.0.2" {
		t.Errorf("expected 10.8.0.2, got %s", ip)
	}
}

func TestAllocateIPGap(t *testing.T) {
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32"}},
		{UserData: ClientData{AllowedIPs: "10.8.0.4/32"}},
	}

	ip, err := allocateIP(nil, clients)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.0.3" {
		t.Errorf("expected 10.8.0.3 (gap fill), got %s", ip)
	}
}

func TestAllocateIPDualStack(t *testing.T) {
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, fd00:a::2/128"}},
		{UserData: ClientData{AllowedIPs: "10.8.0.3/32, fd00:a::3/128"}},
	}

	ip, err := allocateIP(nil, clients)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.0.4" {
		t.Errorf("expected 10.8.0.4, got %s", ip)
	}
}

// Адрес должен выделяться в подсети сервера (как настроен Amnezia: 10.8.1.0/24),
// а не в захардкоженной 10.8.0.0/22.
func TestAllocateIPServerSubnet(t *testing.T) {
	srvParams := &ServerParams{
		Address:        "10.8.1.0/24",
		PeerAllowedIPs: []string{"10.8.1.1/32"}, // клиент, созданный самим Amnezia
	}
	ip, err := allocateIP(srvParams, nil)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	// .0 — адрес сервера, .1 — занят пиром → первый свободный .2.
	if ip != "10.8.1.2" {
		t.Errorf("expected 10.8.1.2, got %s", ip)
	}
}

// Занятые адреса учитываются из реальных [Peer]-секций, даже если clientsTable пуст.
func TestAllocateIPServerSubnetGap(t *testing.T) {
	srvParams := &ServerParams{
		Address:        "10.8.1.0/24",
		PeerAllowedIPs: []string{"10.8.1.1/32", "10.8.1.2/32", "10.8.1.4/32"},
	}
	ip, err := allocateIP(srvParams, nil)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.1.3" {
		t.Errorf("expected 10.8.1.3 (gap fill), got %s", ip)
	}
}

// Сервер на .1 (стандартная раскладка Amnezia) — .1 не выдаётся.
func TestAllocateIPServerSubnetServerOnDotOne(t *testing.T) {
	srvParams := &ServerParams{Address: "10.8.1.1/24"}
	ip, err := allocateIP(srvParams, nil)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.1.2" {
		t.Errorf("expected 10.8.1.2, got %s", ip)
	}
}

func TestAllocateIPv6(t *testing.T) {
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, fd00:a::2/128"}},
		{UserData: ClientData{AllowedIPs: "10.8.0.3/32, fd00:a::3/128"}},
	}

	alloc, err := allocateIPv6(clients, "fd00:a::", nil)
	if err != nil {
		t.Fatalf("allocateIPv6 failed: %v", err)
	}
	if alloc.ClientAddr != "fd00:a::4" {
		t.Errorf("expected fd00:a::4, got %s", alloc.ClientAddr)
	}
	if alloc.AllowedMask != 128 {
		t.Errorf("expected mask 128, got %d", alloc.AllowedMask)
	}
}

func TestAllocateIPv6Empty(t *testing.T) {
	alloc, err := allocateIPv6(nil, "fd00:a::", nil)
	if err != nil {
		t.Fatalf("allocateIPv6 failed: %v", err)
	}
	if alloc.ClientAddr != "fd00:a::2" {
		t.Errorf("expected fd00:a::2, got %s", alloc.ClientAddr)
	}
}

func TestAllocateIPv6Subnet112(t *testing.T) {
	// /96 pool → allocates /112 subnets per client
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, 2a01:db8::1:0/112"}},
	}

	alloc, err := allocateIPv6(clients, "2a01:db8::/96", nil)
	if err != nil {
		t.Fatalf("allocateIPv6 /112 failed: %v", err)
	}
	// ::1:0 is taken, so should get ::2:1 (second subnet, first usable)
	if alloc.ClientAddr != "2a01:db8::2:1" {
		t.Errorf("expected 2a01:db8::2:1, got %s", alloc.ClientAddr)
	}
	if alloc.AllowedMask != 112 {
		t.Errorf("expected mask 112, got %d", alloc.AllowedMask)
	}
	if alloc.SubnetBase != "2a01:db8::2:0" {
		t.Errorf("expected subnet base 2a01:db8::2:0, got %s", alloc.SubnetBase)
	}
}

func TestAllocateIPv6Subnet112Empty(t *testing.T) {
	alloc, err := allocateIPv6(nil, "2a01:db8::/96", nil)
	if err != nil {
		t.Fatalf("allocateIPv6 /112 empty failed: %v", err)
	}
	// First client gets subnet 1: prefix::1:1
	if alloc.ClientAddr != "2a01:db8::1:1" {
		t.Errorf("expected 2a01:db8::1:1, got %s", alloc.ClientAddr)
	}
	if alloc.SubnetBase != "2a01:db8::1:0" {
		t.Errorf("expected subnet base 2a01:db8::1:0, got %s", alloc.SubnetBase)
	}
}

func TestAllocateIPv6CIDR(t *testing.T) {
	// /112 or larger CIDR → allocates individual addresses
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, 2a01:db8::1:1/128"}},
	}

	alloc, err := allocateIPv6(clients, "2a01:db8::1:0/112", nil)
	if err != nil {
		t.Fatalf("allocateIPv6 /112 addr failed: %v", err)
	}
	// ::1:1 is taken, should get ::1:2
	if alloc.ClientAddr != "2a01:db8::1:2" {
		t.Errorf("expected 2a01:db8::1:2, got %s", alloc.ClientAddr)
	}
	if alloc.AllowedMask != 128 {
		t.Errorf("expected mask 128, got %d", alloc.AllowedMask)
	}
}

func TestAddHostToIPv6(t *testing.T) {
	tests := []struct {
		base   string
		hostID int
		want   string
	}{
		{"2a01:db8::4000", 1, "2a01:db8::4001"},
		{"2a01:db8::4000", 256, "2a01:db8::4100"},
		{"2a01:db8::4000", 16382, "2a01:db8::7ffe"},
		{"fd00::", 2, "fd00::2"},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.base)
		if ip == nil {
			t.Fatalf("net.ParseIP(%s) returned nil", tt.base)
		}
		ip = ip.To16()
		addHostToIPv6(ip, tt.hostID)
		if ip.String() != tt.want {
			t.Errorf("addHostToIPv6(%s, %d) = %s, want %s", tt.base, tt.hostID, ip.String(), tt.want)
		}
	}
}

func TestGenerateAWGParams(t *testing.T) {
	params := generateAWGParams()

	requiredKeys := []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"}
	for _, key := range requiredKeys {
		val, ok := params[key]
		if !ok {
			t.Errorf("missing key: %s", key)
			continue
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			t.Errorf("key %s not a number: %s", key, val)
			continue
		}

		switch key {
		case "Jc":
			if n < 3 || n > 8 {
				t.Errorf("Jc=%d out of range [3,8]", n)
			}
		case "Jmin":
			if n < 40 || n > 80 {
				t.Errorf("Jmin=%d out of range [40,80]", n)
			}
		case "Jmax":
			if n < 80 || n > 120 {
				t.Errorf("Jmax=%d out of range [80,120]", n)
			}
		case "S1", "S2", "S3":
			if n < 15 || n > 150 {
				t.Errorf("%s=%d out of range [15,150]", key, n)
			}
		case "S4":
			if n < 4 || n > 12 {
				t.Errorf("S4=%d out of range [4,12]", n)
			}
		}
	}
}

func TestBuildServerConf(t *testing.T) {
	params := map[string]string{
		"Jc": "4", "Jmin": "50", "Jmax": "100",
		"S1": "30", "S2": "60", "S3": "45", "S4": "8",
		"H1": "111", "H2": "222", "H3": "333", "H4": "444",
	}

	// Without IPv6
	conf := buildServerConf("testPrivKey=", 51820, "eth0", params, "", "", AWGVersion2)
	mustContain := []string{
		"[Interface]",
		"PrivateKey = testPrivKey=",
		"Address = 10.8.0.1/22",
		"ListenPort = 51820",
		"Jc = 4",
		"S3 = 45",
		"S4 = 8",
		"MASQUERADE",
	}
	for _, s := range mustContain {
		if !strings.Contains(conf, s) {
			t.Errorf("config missing: %s\n\nFull config:\n%s", s, conf)
		}
	}
	if strings.Contains(conf, "ip6tables") {
		t.Error("should not contain ip6tables without IPv6")
	}
	// PostUp should be idempotent (use -C check)
	if !strings.Contains(conf, "-C FORWARD") {
		t.Error("PostUp should use idempotent -C check")
	}

	// With IPv6 (same subnet = /48 or /56 case)
	confV6 := buildServerConf("testPrivKey=", 51820, "eth0", params, ulaFallbackCIDR, ulaFallbackCIDR, AWGVersion2)
	if !strings.Contains(confV6, ulaFallbackCIDR) {
		t.Error("IPv6 address not in config")
	}
	if !strings.Contains(confV6, "ip6tables") {
		t.Error("ip6tables missing with IPv6 enabled")
	}
	// Same ifaceAddr and clientSubnet — no explicit route needed
	if strings.Contains(confV6, "ip -6 route") {
		t.Error("should not add explicit route when ifaceAddr == clientSubnet")
	}

	// With IPv6 (/64 case — different ifaceAddr and clientSubnet)
	confV6_64 := buildServerConf("testPrivKey=", 51820, "eth0", params, "2a01:db8::1/64", "2a01:db8::4000/114", AWGVersion2)
	if !strings.Contains(confV6_64, "2a01:db8::1/64") {
		t.Error("IPv6 iface address not in config")
	}
	if !strings.Contains(confV6_64, "ip -6 route") {
		t.Error("should add explicit route for /64 case")
	}
	if !strings.Contains(confV6_64, "2a01:db8::4000/114") {
		t.Error("client subnet route not in PostUp")
	}
}

func TestCalculateVPNv6Subnet(t *testing.T) {
	tests := []struct {
		name             string
		serverIPv6       string
		prefixLen        int
		wantIfaceAddr    string
		wantClientSubnet string
		wantServerIP     string
	}{
		{
			name:             "/48 prefix — separate /64",
			serverIPv6:       "2a01:db8:1234::",
			prefixLen:        48,
			wantIfaceAddr:    "2a01:db8:1234:1::1/112",
			wantClientSubnet: "2a01:db8:1234:1::1/112",
		},
		{
			name:       "/64 prefix — uses /96 pool for /112-per-client",
			serverIPv6: "2a01:db8:1234:5678::1",
			prefixLen:  64,
		},
		{
			name:             "invalid IP falls back to ULA",
			serverIPv6:       "invalid",
			prefixLen:        48,
			wantIfaceAddr:    ulaFallbackCIDR,
			wantClientSubnet: ulaFallbackCIDR,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifaceAddr, clientSubnet, serverIP := calculateVPNv6Subnet(tt.serverIPv6, tt.prefixLen)

			if tt.wantIfaceAddr != "" && ifaceAddr != tt.wantIfaceAddr {
				t.Errorf("ifaceAddr: expected %s, got %s", tt.wantIfaceAddr, ifaceAddr)
			}
			if tt.wantClientSubnet != "" && clientSubnet != tt.wantClientSubnet {
				t.Errorf("clientSubnet: expected %s, got %s", tt.wantClientSubnet, clientSubnet)
			}
			if serverIP == "" {
				t.Error("server IP should not be empty")
			}

			// /64 case: ifaceAddr should be /64, clientSubnet should be /96 (pool for /112 subnets)
			if tt.prefixLen == 64 && tt.serverIPv6 != "invalid" {
				if !strings.HasSuffix(ifaceAddr, "/64") {
					t.Errorf("/64 case: ifaceAddr should end with /64, got %s", ifaceAddr)
				}
				if !strings.HasSuffix(clientSubnet, "/96") {
					t.Errorf("/64 case: clientSubnet should end with /96, got %s", clientSubnet)
				}
				if ifaceAddr == clientSubnet {
					t.Error("/64 case: ifaceAddr and clientSubnet should differ")
				}
			}
		})
	}
}

func TestBuildClientConfig(t *testing.T) {
	params := &ServerParams{
		PublicKey: "serverPubKey=",
		AWGParams: map[string]string{
			"Jc": "4", "Jmin": "40", "Jmax": "70",
			"S1": "52", "S2": "27",
			"H1": "1", "H2": "2", "H3": "3", "H4": "4",
		},
	}

	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params)

	mustContain := []string{
		"[Interface]",
		"PrivateKey = clientPrivKey=",
		"Address = 10.8.1.5/32",
		"DNS = 8.8.8.8",
		"Jc = 4",
		"Jmin = 40",
		"Jmax = 70",
		"S1 = 52",
		"S2 = 27",
		"H1 = 1",
		"[Peer]",
		"PublicKey = serverPubKey=",
		"PresharedKey = pskKey=",
		"Endpoint = 1.2.3.4:51820",
		"AllowedIPs = 0.0.0.0/0",
	}

	for _, s := range mustContain {
		if !contains(conf, s) {
			t.Errorf("config missing: %s\n\nFull config:\n%s", s, conf)
		}
	}
}

func TestBuildClientConfigDualStack(t *testing.T) {
	params := &ServerParams{
		PublicKey: "serverPubKey=",
		AWGParams: map[string]string{
			"Jc": "4", "Jmin": "40", "Jmax": "70",
			"S1": "52", "S2": "27",
			"H1": "1", "H2": "2", "H3": "3", "H4": "4",
		},
	}

	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.0.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params, "fd00:a::5")

	if !strings.Contains(conf, "Address = 10.8.0.5/32, fd00:a::5/128") {
		t.Errorf("dual-stack address not found in config:\n%s", conf)
	}
	if !strings.Contains(conf, "2001:4860:4860::8888") {
		t.Errorf("IPv6 DNS not found in config:\n%s", conf)
	}
}

// Параметры AWG 2.0 (S3/S4 + I1-I5) должны доезжать до клиентского конфига.
func TestBuildClientConfigV2Params(t *testing.T) {
	params := &ServerParams{
		PublicKey:  "serverPubKey=",
		ListenPort: "51820",
		AWGParams: map[string]string{
			"Jc": "4", "Jmin": "40", "Jmax": "70",
			"S1": "52", "S2": "27", "S3": "45", "S4": "8",
			"H1": "1", "H2": "2", "H3": "3", "H4": "4",
			"I1": "100", "I2": "200", "I3": "300", "I4": "400", "I5": "500",
		},
	}

	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params)

	for _, s := range []string{"S3 = 45", "S4 = 8", "I1 = 100", "I5 = 500"} {
		if !strings.Contains(conf, s) {
			t.Errorf("config missing: %s\n\nFull config:\n%s", s, conf)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && searchString(haystack, needle)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestBuildAmneziaVPNURI(t *testing.T) {
	params := &ServerParams{
		PublicKey:  "serverPubKey=",
		ListenPort: "51820",
		AWGParams: map[string]string{
			"Jc": "4", "Jmin": "40", "Jmax": "70",
			"S1": "52", "S2": "27",
			"H1": "1", "H2": "2", "H3": "3", "H4": "4",
		},
	}

	uri, _, err := BuildAmneziaVPNURI("clientPrivKey=", "clientPubKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "TestServer", "8.8.8.8", "8.8.4.4", params)
	if err != nil {
		t.Fatalf("BuildAmneziaVPNURI failed: %v", err)
	}

	// Must start with vpn://
	if !strings.HasPrefix(uri, "vpn://") {
		t.Fatalf("URI must start with vpn://, got: %s", uri[:20])
	}

	cfg := decodeVPNURI(t, uri)

	// Verify top-level fields
	if cfg.HostName != "1.2.3.4" {
		t.Errorf("expected hostName=1.2.3.4, got %s", cfg.HostName)
	}
	if cfg.DNS1 != "8.8.8.8" {
		t.Errorf("expected dns1=8.8.8.8, got %s", cfg.DNS1)
	}
	if cfg.DefaultContainer != "amnezia-awg" {
		t.Errorf("expected defaultContainer=amnezia-awg, got %s", cfg.DefaultContainer)
	}
	if cfg.Description != "TestServer" {
		t.Errorf("expected description=TestServer, got %s", cfg.Description)
	}
	if len(cfg.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(cfg.Containers))
	}

	awg := cfg.Containers[0].AWG

	if awg.Port != "51820" {
		t.Errorf("expected port=51820, got %s", awg.Port)
	}
	// AWG params at container level
	if awg.Params["Jc"] != "4" {
		t.Errorf("expected Jc=4, got %s", awg.Params["Jc"])
	}

	// last_config must be a valid JSON string
	lc := awg.LastConfig
	var lcParsed map[string]interface{}
	if err := json.Unmarshal([]byte(lc), &lcParsed); err != nil {
		t.Fatalf("last_config is not valid JSON: %v", err)
	}
	// Must have config field with WG+AWG INI text
	configStr, ok := lcParsed["config"].(string)
	if !ok {
		t.Fatal("last_config missing 'config' field")
	}
	if !strings.Contains(configStr, "[Interface]") {
		t.Error("last_config.config missing [Interface]")
	}
	if !strings.Contains(configStr, "Jc = 4") {
		t.Error("last_config.config missing AWG param Jc")
	}
	// Must have key fields
	if lcParsed["client_priv_key"] != "clientPrivKey=" {
		t.Error("last_config missing client_priv_key")
	}
	if lcParsed["server_pub_key"] != "serverPubKey=" {
		t.Error("last_config missing server_pub_key")
	}
}

// decodeVPNURI разбирает vpn://-ссылку обратно в конфиг AmneziaVPN:
// base64url → 4-байтный Qt-заголовок → zlib → JSON.
func decodeVPNURI(t *testing.T, uri string) amneziaVPNConfig {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "vpn://"))
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) < 4 {
		t.Fatalf("compressed data too short: %d bytes", len(decoded))
	}

	r, err := zlib.NewReader(bytes.NewReader(decoded[4:]))
	if err != nil {
		t.Fatalf("zlib reader failed: %v", err)
	}
	defer r.Close()

	jsonBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("zlib read failed: %v", err)
	}

	var cfg amneziaVPNConfig
	if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	return cfg
}

// testPrivKey — валидный Curve25519-ключ (см. TestDerivePublicKey).
// Нужен там, где parseServerConfig выводит из него публичный ключ сервера.
const testPrivKey = "EIW3XjQle9t8v29XijOKQo2ZQxS2+Xxq6Hr51xu4cFI="

// v3Params — набор параметров сервера AWG 3.0.
func v3Params() *ServerParams {
	return &ServerParams{
		PublicKey:  "serverPubKey=",
		ListenPort: "51820",
		AWGParams: map[string]string{
			"Jc": "4", "Jmin": "40", "Jmax": "70",
			"S1": "52", "S2": "27", "S3": "45", "S4": "8",
			"H1": "100-200", "H2": "300-400", "H3": "500-600", "H4": "700-800",
			"HeaderProtectionKey":    "aGVhZGVyS2V5MTIzNDU2Nzg5MA==",
			"ContentPaddingAddition": "64",
			"RekeyAfterTime":         "120",
			"RekeyTimeout":           "5",
			"RejectAfterTime":        "180",
			"KeepaliveTimeout":       "10",
			"MaxHandshakeAttempts":   "18",
		},
	}
}

// Регрессия: для типового awg0.conf от Amnezia (AWG 2.0, docker) клиентский
// конфиг должен совпадать побайтово с тем, что бот выдавал до перехода на
// зеркалирование параметров. Служебные ключи awg-quick в него не просачиваются.
func TestBuildClientConfigAmneziaV2Golden(t *testing.T) {
	serverConf := `[Interface]
Address = 10.8.1.0/24
ListenPort = 51820
PrivateKey = ` + testPrivKey + `
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 131
S2 = 45
S3 = 88
S4 = 8
H1 = 1148947297
H2 = 1214747399
H3 = 1710862354
H4 = 1876997419
PostUp = iptables -A FORWARD -i %i -j ACCEPT; sysctl -w net.ipv4.ip_forward=1
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = AAA=
PresharedKey = pskA=
AllowedIPs = 10.8.1.2/32
`

	params, err := parseServerConfig(serverConf)
	if err != nil {
		t.Fatalf("parseServerConfig failed: %v", err)
	}
	if params.Version != AWGVersion2 {
		t.Errorf("Version = %v, ожидалось AWG 2.0", params.Version)
	}

	got := BuildClientConfig("clientPriv=", "psk=", "10.8.1.5", "1.2.3.4", params.ListenPort, "8.8.8.8", "8.8.4.4", params)

	want := `[Interface]
PrivateKey = clientPriv=
Address = 10.8.1.5/32
DNS = 8.8.8.8, 8.8.4.4
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 131
S2 = 45
S3 = 88
S4 = 8
H1 = 1148947297
H2 = 1214747399
H3 = 1710862354
H4 = 1876997419

[Peer]
PublicKey = v54/dW01wtlvXJ51Qic9QYe4T2dZmyg96/WuLFCkcgU=
PresharedKey = psk=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

	if got != want {
		t.Errorf("клиентский конфиг разъехался с эталоном.\n--- получено ---\n%s\n--- ожидалось ---\n%s", got, want)
	}
}

// Команда детекта версии обязана завершаться с кодом 0 даже когда ни awg, ни
// модуля ядра нет: exit status пайплайна — это код grep, и без завершающего
// `; true` SSHRun считал бы это ошибкой и выбрасывал вывод `awg --version`.
// Из-за этого версия не определялась ни на одном docker-сервере.
func TestDetectAWGVersionCommandExitsZero(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh недоступен")
	}

	// Тот же скрипт, что в detectAWGVersion, но без внешней обёртки sh -c '...'.
	const script = `awg --version 2>/dev/null; modinfo amneziawg 2>/dev/null | grep "^version:"; true`
	if err := exec.Command(sh, "-c", script).Run(); err != nil {
		t.Errorf("команда детекта версии завершилась с ошибкой: %v", err)
	}

	if !strings.Contains(awgVersionProbeCmd, "; true") {
		t.Error("в команде детекта версии потерялся завершающий `; true`")
	}
}

func TestFirstIPv4CIDR(t *testing.T) {
	tests := []struct{ in, want string }{
		{"10.8.0.1/22", "10.8.0.1/22"},
		{"10.8.0.1/22, 2a01:db8::1/64", "10.8.0.1/22"},
		{"2a01:db8::1/64, 10.8.0.1/22", "10.8.0.1/22"},
		{"2a01:db8::1/64", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstIPv4CIDR(tt.in); got != tt.want {
			t.Errorf("firstIPv4CIDR(%q) = %q, ожидалось %q", tt.in, got, tt.want)
		}
	}
}

// Dual-stack строка Address не должна ронять выделение в запасной пул 10.8.0.0/22.
func TestAllocateIPDualStackServerAddress(t *testing.T) {
	srvParams := &ServerParams{Address: "10.9.0.1/24, 2a01:db8::1/64"}
	ip, err := allocateIP(srvParams, nil)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.9.0.2" {
		t.Errorf("ожидался адрес из реальной подсети 10.9.0.0/24, получено %s", ip)
	}
}

// При /48 и /56 пул клиентов совпадает с подсетью сервера, поэтому собственный
// адрес интерфейса обязан считаться занятым.
func TestAllocateIPv6SkipsServerAddress(t *testing.T) {
	srvParams := &ServerParams{Address: "10.8.0.1/22, 2a01:db8:1234:1::1/112"}

	alloc, err := allocateIPv6(nil, "2a01:db8:1234:1::1/112", srvParams)
	if err != nil {
		t.Fatalf("allocateIPv6 failed: %v", err)
	}
	if alloc.ClientAddr == "2a01:db8:1234:1::1" {
		t.Fatal("клиенту выдан собственный IPv6-адрес сервера")
	}
	if alloc.ClientAddr != "2a01:db8:1234:1::2" {
		t.Errorf("ожидался 2a01:db8:1234:1::2, получено %s", alloc.ClientAddr)
	}
}

// IPv6 из [Peer]-секций тоже занят, даже если этих клиентов нет в clientsTable.
func TestAllocateIPv6UsesPeerAddresses(t *testing.T) {
	srvParams := &ServerParams{
		PeerAllowedIPs: []string{"10.8.1.2/32, 2a01:db8::1:0/112"},
	}

	alloc, err := allocateIPv6(nil, "2a01:db8::/96", srvParams)
	if err != nil {
		t.Fatalf("allocateIPv6 failed: %v", err)
	}
	if alloc.SubnetBase != "2a01:db8::2:0" {
		t.Errorf("подсеть из [Peer] должна считаться занятой; получено %s", alloc.SubnetBase)
	}
}

// ULA-фолбэк обязан быть валидным IPv6: awg-quick не поднимет интерфейс с
// невалидным адресом, а аллокатор сорвётся в строковый legacy-режим.
func TestULAFallbackIsValidIPv6(t *testing.T) {
	if ip := net.ParseIP(ulaFallbackAddr); ip == nil {
		t.Fatalf("ulaFallbackAddr %q — не валидный IPv6", ulaFallbackAddr)
	}
	if _, _, err := net.ParseCIDR(ulaFallbackCIDR); err != nil {
		t.Fatalf("ulaFallbackCIDR %q не парсится: %v", ulaFallbackCIDR, err)
	}

	ifaceAddr, clientSubnet, serverIP := calculateVPNv6Subnet("invalid", 48)
	for _, s := range []string{ifaceAddr, clientSubnet} {
		if _, _, err := net.ParseCIDR(s); err != nil {
			t.Errorf("фолбэк вернул непарсящийся CIDR %q: %v", s, err)
		}
	}
	if net.ParseIP(serverIP) == nil {
		t.Errorf("фолбэк вернул невалидный адрес сервера %q", serverIP)
	}
}

// Парсер awg-quick регистронезависим: служебный ключ в нестандартном регистре
// не должен уехать в клиентский конфиг, а параметр — потеряться.
func TestParseServerConfigCaseInsensitive(t *testing.T) {
	conf := `[interface]
privatekey = ` + testPrivKey + `
address = 10.8.1.0/24
listenport = 51820
postup = iptables -A FORWARD -i %i -j ACCEPT
MTU = 1420
jc = 4
s1 = 52

[peer]
publickey = AAA=
allowedips = 10.8.1.2/32
`
	params, err := parseServerConfig(conf)
	if err != nil {
		t.Fatalf("parseServerConfig failed: %v", err)
	}

	if params.PrivateKey != testPrivKey || params.Address != "10.8.1.0/24" || params.ListenPort != "51820" {
		t.Errorf("служебные поля не разобраны: %+v", params)
	}
	for _, bad := range []string{"postup", "PostUp", "MTU", "mtu"} {
		if _, ok := params.AWGParams[bad]; ok {
			t.Errorf("служебный ключ %q попал в AWGParams", bad)
		}
	}
	// Известные параметры приводятся к каноническому написанию, иначе они
	// выпали бы из clientParamOrder и не доехали бы до клиента.
	if params.AWGParams["Jc"] != "4" || params.AWGParams["S1"] != "52" {
		t.Errorf("параметры не приведены к каноническому виду: %v", params.AWGParams)
	}
	if len(params.ExtraParamOrder) != 0 {
		t.Errorf("известные параметры не должны считаться неизвестными: %v", params.ExtraParamOrder)
	}
	if len(params.Peers) != 1 || params.Peers[0].PublicKey != "AAA=" {
		t.Errorf("секция [peer] не разобрана: %+v", params.Peers)
	}

	conf2 := BuildClientConfig("priv=", "psk=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params)
	if strings.Contains(strings.ToLower(conf2), "postup") {
		t.Errorf("PostUp просочился в клиентский конфиг:\n%s", conf2)
	}
	if !strings.Contains(conf2, "Jc = 4") {
		t.Errorf("параметр Jc потерялся в клиентском конфиге:\n%s", conf2)
	}
}

// IPv6-адрес в Endpoint обязан быть в квадратных скобках.
func TestBuildClientConfigIPv6Endpoint(t *testing.T) {
	params := &ServerParams{PublicKey: "srv=", AWGParams: map[string]string{"Jc": "4"}}

	conf := BuildClientConfig("priv=", "psk=", "10.8.1.5", "2a01:db8::1", "51820", "8.8.8.8", "8.8.4.4", params)
	if !strings.Contains(conf, "Endpoint = [2a01:db8::1]:51820") {
		t.Errorf("IPv6-endpoint без скобок:\n%s", conf)
	}

	conf4 := BuildClientConfig("priv=", "psk=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params)
	if !strings.Contains(conf4, "Endpoint = 1.2.3.4:51820") {
		t.Errorf("IPv4-endpoint изменился:\n%s", conf4)
	}
}

// Конфиг внутри vpn:// должен нести те же адреса, что и выданный .conf.
func TestBuildAmneziaVPNURIIncludesClientIPv6(t *testing.T) {
	params := v3Params()

	uri, _, err := BuildAmneziaVPNURI("priv=", "pub=", "psk=", "10.8.1.5", "1.2.3.4", "51820", "S", "8.8.8.8", "8.8.4.4", params, "2a01:db8::1:1", "112")
	if err != nil {
		t.Fatalf("BuildAmneziaVPNURI failed: %v", err)
	}

	cfg := decodeVPNURI(t, uri)
	var lc map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.Containers[0].AWG.LastConfig), &lc); err != nil {
		t.Fatalf("last_config is not valid JSON: %v", err)
	}
	configStr, _ := lc["config"].(string)
	if !strings.Contains(configStr, "Address = 10.8.1.5/32, 2a01:db8::1:1/112") {
		t.Errorf("IPv6 клиента не попал в конфиг внутри URI:\n%s", configStr)
	}
}

// Прежняя структура объявляла I1-I5 без omitempty, поэтому они присутствовали
// всегда. Для серверов AWG 1.0 их нельзя терять при переходе на map.
func TestBuildAmneziaVPNURIAlwaysHasIKeys(t *testing.T) {
	v1 := &ServerParams{
		PublicKey:  "serverPubKey=",
		ListenPort: "51820",
		AWGParams: map[string]string{
			"Jc": "4", "Jmin": "40", "Jmax": "70", "S1": "52", "S2": "27",
			"H1": "1", "H2": "2", "H3": "3", "H4": "4",
		},
	}

	uri, _, err := BuildAmneziaVPNURI("priv=", "pub=", "psk=", "10.8.1.5", "1.2.3.4", "51820", "S", "8.8.8.8", "8.8.4.4", v1)
	if err != nil {
		t.Fatalf("BuildAmneziaVPNURI failed: %v", err)
	}

	cfg := decodeVPNURI(t, uri)
	if cfg.DefaultContainer != "amnezia-awg" {
		t.Errorf("для 1.0 ожидался контейнер amnezia-awg, получено %s", cfg.DefaultContainer)
	}
	awg := cfg.Containers[0].AWG
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if _, ok := awg.Params[k]; !ok {
			t.Errorf("ключ %s пропал из контейнера awg", k)
		}
	}
	// В сам конфиг пустые I1-I5 при этом попадать не должны — awg-quick на них падает.
	var lc map[string]interface{}
	if err := json.Unmarshal([]byte(awg.LastConfig), &lc); err != nil {
		t.Fatalf("last_config is not valid JSON: %v", err)
	}
	if configStr, _ := lc["config"].(string); strings.Contains(configStr, "I1 = \n") {
		t.Errorf("пустой I1 попал в текст конфига:\n%s", configStr)
	}
}

// Откат вправе удалять директорию конфигов только если создал её сам.
func TestConfDirPreexisted(t *testing.T) {
	created := &InstallLog{Steps: []InstallStep{
		{StepName: "Create config directory", Output: "", Success: true},
	}}
	if confDirPreexisted(created) {
		t.Error("директории не было — откат должен её удалять")
	}

	existed := &InstallLog{Steps: []InstallStep{
		{StepName: "Create config directory", Output: confDirExistedMarker + "\n", Success: true},
	}}
	if !confDirPreexisted(existed) {
		t.Error("директория существовала до установки — удалять её нельзя")
	}

	if confDirPreexisted(&InstallLog{}) {
		t.Error("пустой лог не должен считаться признаком существующей директории")
	}
}

func TestParseToolsVersion(t *testing.T) {
	tests := []struct {
		out     string
		want    AWGVersion
		wantRaw string
	}{
		{"amneziawg-tools v3.1.20260812\n", AWGVersion31, "3.1.20260812"},
		{"amneziawg-tools v3.0.20260730\n", AWGVersion3, "3.0.20260730"},
		{"amneziawg-tools v2.0.20250705\n", AWGVersion2, "2.0.20250705"},
		{"amneziawg-tools v1.5.20250704\n", AWGVersion15, "1.5.20250704"},
		{"wireguard-tools v1.0.20210914\n", AWGVersion1, "1.0.20210914"},
		{"", AWGVersionUnknown, ""},
		{"sh: awg: not found", AWGVersionUnknown, ""},
	}
	for _, tt := range tests {
		got, raw := parseToolsVersion(tt.out)
		if got != tt.want || raw != tt.wantRaw {
			t.Errorf("parseToolsVersion(%q) = (%v, %q), ожидалось (%v, %q)", tt.out, got, raw, tt.want, tt.wantRaw)
		}
	}
}

func TestParseKmodVersion(t *testing.T) {
	tests := []struct {
		out     string
		want    AWGVersion
		wantRaw string
	}{
		{"version:        3.1.20260812-01\n", AWGVersion31, "3.1.20260812-01"},
		{"version:        3.0.20260731-04\n", AWGVersion3, "3.0.20260731-04"},
		{"version: 2.0.20250705\n", AWGVersion2, "2.0.20250705"},
		{"", AWGVersionUnknown, ""},
	}
	for _, tt := range tests {
		got, raw := parseKmodVersion(tt.out)
		if got != tt.want || raw != tt.wantRaw {
			t.Errorf("parseKmodVersion(%q) = (%v, %q), ожидалось (%v, %q)", tt.out, got, raw, tt.want, tt.wantRaw)
		}
	}
}

// Эффективная версия — более ранняя из tools и модуля ядра: tools 3.0 отправят
// HeaderProtectionKey, а модуль 2.0 его отвергнет.
func TestParseAWGVersionOutputTakesMin(t *testing.T) {
	info := parseAWGVersionOutput("amneziawg-tools v3.0.20260730\nversion:        2.0.20250705\n")
	if info.Version != AWGVersion2 {
		t.Errorf("ожидалась AWG 2.0 (минимум из tools 3.0 и kmod 2.0), получено %v", info.Version)
	}
	if info.ToolsRaw != "3.0.20260730" || info.KmodRaw != "2.0.20250705" {
		t.Errorf("сырые версии разобраны неверно: tools=%q kmod=%q", info.ToolsRaw, info.KmodRaw)
	}

	// Docker: модуля нет (userspace amneziawg-go) — берём версию tools.
	docker := parseAWGVersionOutput("amneziawg-tools v2.0.20250705\n")
	if docker.Version != AWGVersion2 {
		t.Errorf("без modinfo ожидалась версия tools 2.0, получено %v", docker.Version)
	}
	if docker.KmodRaw != "" {
		t.Errorf("KmodRaw должен быть пуст, получено %q", docker.KmodRaw)
	}

	// Минорная версия участвует в сравнении так же, как мажорная: tools 3.1
	// отправят RandomTrailers, а модуль 3.0 отвергнет неизвестный атрибут.
	mixed := parseAWGVersionOutput("amneziawg-tools v3.1.20260812\nversion:        3.0.20260731-04\n")
	if mixed.Version != AWGVersion3 {
		t.Errorf("ожидалась AWG 3.0 (минимум из tools 3.1 и kmod 3.0), получено %v", mixed.Version)
	}

	full31 := parseAWGVersionOutput("amneziawg-tools v3.1.20260812\nversion:        3.1.20260812-01\n")
	if full31.Version != AWGVersion31 {
		t.Errorf("ожидалась AWG 3.1, получено %v", full31.Version)
	}
}

// Хронология версий: 1.0 → 1.5 → 2.0 → 3.0 → 3.1. Значение AWGVersion15 и
// AWGVersion31 выбиваются из неё числом, поэтому порядок даёт только versionRank.
func TestVersionRankAndString(t *testing.T) {
	order := []AWGVersion{AWGVersionUnknown, AWGVersion1, AWGVersion15, AWGVersion2, AWGVersion3, AWGVersion31}
	for i := 1; i < len(order); i++ {
		if versionRank(order[i-1]) >= versionRank(order[i]) {
			t.Errorf("%v должна идти раньше %v (ранги %d и %d)",
				order[i-1], order[i], versionRank(order[i-1]), versionRank(order[i]))
		}
	}

	names := map[AWGVersion]string{
		AWGVersionUnknown: "AWG ?",
		AWGVersion1:       "AWG 1.0",
		AWGVersion15:      "AWG 1.5",
		AWGVersion2:       "AWG 2.0",
		AWGVersion3:       "AWG 3.0",
		AWGVersion31:      "AWG 3.1",
	}
	for v, want := range names {
		if got := v.String(); got != want {
			t.Errorf("String(%d) = %q, ожидалось %q", int(v), got, want)
		}
	}

	if minAWGVersion(AWGVersion31, AWGVersion3) != AWGVersion3 {
		t.Error("более ранняя из 3.1 и 3.0 — это 3.0")
	}
}

// Параметры 3.1 должны быть видны версии 3.1 и не видны 3.0, а параметры 3.0 —
// обеим.
func TestVersionHasParam31(t *testing.T) {
	if versionHasParam(AWGVersion3, AWGVersion31) {
		t.Error("RandomTrailers (3.1) не должен считаться доступным в 3.0")
	}
	if !versionHasParam(AWGVersion31, AWGVersion31) {
		t.Error("параметры 3.1 должны быть доступны в 3.1")
	}
	if !versionHasParam(AWGVersion31, AWGVersion3) {
		t.Error("параметры 3.0 должны быть доступны в 3.1")
	}
	if versionHasParam(AWGVersion15, AWGVersion31) {
		t.Error("в тупиковой ветке 1.5 параметров 3.1 нет")
	}
}

func TestDeriveConfigVersion(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
		want   AWGVersion
	}{
		{"HeaderProtectionKey → 3.0", map[string]string{"S1": "52", "S3": "45", "HeaderProtectionKey": "aaa="}, AWGVersion3},
		{"ContentPaddingAddition → 3.0", map[string]string{"S1": "52", "ContentPaddingAddition": "64"}, AWGVersion3},
		{"RandomTrailers → 3.1", map[string]string{"S1": "52", "S3": "45", "RandomTrailers": "on"}, AWGVersion31},
		{"DisableCookies → 3.1", map[string]string{"S1": "52", "DisableCookies": "1"}, AWGVersion31},
		{"3.0 + 3.1 → 3.1", map[string]string{"S1": "52", "HeaderProtectionKey": "aaa=", "RandomTrailers": "on"}, AWGVersion31},
		// Выключенный тумблер равнозначен отсутствующему — так же считает и приложение.
		{"RandomTrailers = off → не 3.1", map[string]string{"S1": "52", "S3": "45", "RandomTrailers": "off"}, AWGVersion2},
		{"off + HeaderProtectionKey → 3.0", map[string]string{"S1": "52", "HeaderProtectionKey": "aaa=", "DisableCookies": "off"}, AWGVersion3},
		{"S3 → 2.0", map[string]string{"S1": "52", "S2": "27", "S3": "45"}, AWGVersion2},
		{"S4 → 2.0", map[string]string{"S1": "52", "S4": "8"}, AWGVersion2},
		{"диапазон H1 → 2.0", map[string]string{"S1": "52", "S2": "27", "H1": "100-200"}, AWGVersion2},
		{"Itime → 1.5", map[string]string{"S1": "52", "Itime": "60"}, AWGVersion15},
		{"J1 → 1.5", map[string]string{"S1": "52", "J1": "b0x"}, AWGVersion15},
		{"только S1/S2 → 1.0", map[string]string{"S1": "52", "S2": "27", "H1": "1"}, AWGVersion1},
		{"пусто → Unknown", map[string]string{}, AWGVersionUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveConfigVersion(&ServerParams{AWGParams: tt.params})
			if got != tt.want {
				t.Errorf("deriveConfigVersion = %v, ожидалось %v", got, tt.want)
			}
		})
	}

	if got := deriveConfigVersion(nil); got != AWGVersionUnknown {
		t.Errorf("nil → ожидалось Unknown, получено %v", got)
	}
}

// Неизвестный ключ из [Interface] должен доехать до AWGParams, а служебные
// ключи awg-quick — нет.
func TestReadServerConfigMirrorsUnknownParams(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + testPrivKey + `
Address = 10.8.1.0/24
ListenPort = 51820
DNS = 1.1.1.1, 1.0.0.1
MTU = 1420
Table = off
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT
SaveConfig = false
Jc = 4
S3 = 45
HeaderProtectionKey = aGVhZGVyS2V5
Z9 = future-value

[Peer]
PublicKey = AAA=
AllowedIPs = 10.8.1.2/32
`
	params, err := parseServerConfig(conf)
	if err != nil {
		t.Fatalf("parseServerConfig failed: %v", err)
	}

	for _, key := range []string{"Jc", "S3", "HeaderProtectionKey", "Z9"} {
		if _, ok := params.AWGParams[key]; !ok {
			t.Errorf("параметр %q должен зеркалиться в AWGParams", key)
		}
	}
	if params.AWGParams["Z9"] != "future-value" {
		t.Errorf("Z9 = %q, ожидалось future-value", params.AWGParams["Z9"])
	}
	for _, key := range []string{"PostUp", "PostDown", "MTU", "Table", "SaveConfig", "PrivateKey", "Address", "ListenPort", "DNS"} {
		if _, ok := params.AWGParams[key]; ok {
			t.Errorf("служебный ключ %q не должен попадать в AWGParams", key)
		}
	}

	if len(params.ExtraParamOrder) != 1 || params.ExtraParamOrder[0] != "Z9" {
		t.Errorf("ExtraParamOrder = %v, ожидалось [Z9]", params.ExtraParamOrder)
	}
	if params.DNS != "1.1.1.1, 1.0.0.1" {
		t.Errorf("DNS = %q", params.DNS)
	}
	if params.Version != AWGVersion3 {
		t.Errorf("Version = %v, ожидалось AWG 3.0", params.Version)
	}
	if len(params.Peers) != 1 || params.Peers[0].PublicKey != "AAA=" || params.Peers[0].AllowedIPs != "10.8.1.2/32" {
		t.Errorf("Peers разобраны неверно: %+v", params.Peers)
	}
	if len(params.PeerAllowedIPs) != 1 || params.PeerAllowedIPs[0] != "10.8.1.2/32" {
		t.Errorf("PeerAllowedIPs = %v", params.PeerAllowedIPs)
	}
}

// Известные параметры идут в каноническом порядке, нераспознанные — следом,
// в порядке появления в конфиге сервера.
func TestClientParamOrderExtras(t *testing.T) {
	params := &ServerParams{
		AWGParams: map[string]string{
			"S1": "52", "Jc": "4", "H1": "1",
			"Zz": "1", "Aa": "2",
		},
		ExtraParamOrder: []string{"Zz", "Aa"},
	}

	got := clientParamOrder(params)
	want := []string{"Jc", "S1", "H1", "Zz", "Aa"}
	if len(got) != len(want) {
		t.Fatalf("clientParamOrder = %v, ожидалось %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("clientParamOrder = %v, ожидалось %v", got, want)
		}
	}

	if clientParamOrder(nil) != nil {
		t.Error("nil params → ожидался nil")
	}
}

// serverParamOrder фильтрует по версии: параметры 3.0 не попадают в конфиг 2.0,
// а тупиковая ветка 1.5 стоит особняком в обе стороны.
func TestServerParamOrder(t *testing.T) {
	has := func(keys []string, k string) bool {
		for _, x := range keys {
			if x == k {
				return true
			}
		}
		return false
	}

	v2 := serverParamOrder(AWGVersion2)
	if !has(v2, "S3") || !has(v2, "S4") {
		t.Error("в 2.0 должны быть S3/S4")
	}
	if has(v2, "HeaderProtectionKey") {
		t.Error("параметры 3.0 не должны попадать в конфиг 2.0")
	}
	if has(v2, "I1") {
		t.Error("I1-I5 — клиентские, в серверный конфиг не пишутся")
	}

	v3 := serverParamOrder(AWGVersion3)
	for _, k := range []string{"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "MaxHandshakeAttempts"} {
		if !has(v3, k) {
			t.Errorf("в 3.0 должен быть %s", k)
		}
	}
	if has(v3, "J1") || has(v3, "Itime") {
		t.Error("параметров ветки 1.5 в 3.0 быть не должно")
	}
	if has(v3, "RandomTrailers") || has(v3, "DisableCookies") {
		t.Error("тумблеры 3.1 не должны попадать в конфиг 3.0")
	}

	v31 := serverParamOrder(AWGVersion31)
	for _, k := range []string{"HeaderProtectionKey", "RandomTrailers", "DisableCookies"} {
		if !has(v31, k) {
			t.Errorf("в 3.1 должен быть %s", k)
		}
	}

	v1 := serverParamOrder(AWGVersion1)
	if has(v1, "S3") {
		t.Error("в 1.0 не должно быть S3")
	}
}

// Параметры AWG 3.0 должны доезжать до клиентского конфига без правок кода.
func TestBuildClientConfigV3(t *testing.T) {
	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", v3Params())

	mustContain := []string{
		"HeaderProtectionKey = aGVhZGVyS2V5MTIzNDU2Nzg5MA==",
		"ContentPaddingAddition = 64",
		"RekeyAfterTime = 120",
		"RekeyTimeout = 5",
		"RejectAfterTime = 180",
		"KeepaliveTimeout = 10",
		"MaxHandshakeAttempts = 18",
		// H-параметры копируются как есть — диапазонами, раз на сервере диапазоны.
		"H1 = 100-200",
		"H4 = 700-800",
	}
	for _, s := range mustContain {
		if !strings.Contains(conf, s) {
			t.Errorf("config missing: %s\n\nFull config:\n%s", s, conf)
		}
	}
}

// Серверный awg0.conf в том виде, в каком его пишет AmneziaVPN 5.x с AWG 3.1
// (client/server_scripts/awg/configure_container.sh): I1-I5 там закомментированы,
// а тумблеры идут последними. Бот должен опознать 3.1 и донести весь набор до
// клиента — иначе рукопожатия не будет.
func TestParseServerConfigAmneziaV31(t *testing.T) {
	serverConf := `[Interface]
PrivateKey = ` + testPrivKey + `
Address = 10.8.1.1/24
ListenPort = 51820
Jc = 5
Jmin = 10
Jmax = 50
S1 = 87
S2 = 41
S3 = 33
S4 = 12
H1 = 1204935283-1204935283
H2 = 1685061666-1685061666
H3 = 1301090747-1301090747
H4 = 1978550559-1978550559
HeaderProtectionKey = aGVhZGVyS2V5MTIzNDU2Nzg5MA==
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
# I1 = <r 2>
# I2 =
`
	params, err := parseServerConfig(serverConf)
	if err != nil {
		t.Fatalf("parseServerConfig: %v", err)
	}

	if params.Version != AWGVersion31 {
		t.Errorf("версия конфига = %v, ожидалась AWG 3.1", params.Version)
	}
	if _, ok := params.AWGParams["I1"]; ok {
		t.Error("закомментированный I1 не должен попадать в параметры")
	}
	if len(params.ExtraParamOrder) != 0 {
		t.Errorf("все параметры 3.1 должны быть известны боту, в extra попали: %v", params.ExtraParamOrder)
	}

	// Порядок в клиентском конфиге — как в шаблоне Amnezia: сначала Jc/S/H,
	// затем параметры 3.0, тумблеры 3.1 последними.
	order := clientParamOrder(params)
	want := []string{
		"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
		"HeaderProtectionKey", "ContentPaddingAddition",
		"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
		"MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
	}
	if len(order) != len(want) {
		t.Fatalf("clientParamOrder = %v, ожидалось %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("clientParamOrder = %v, ожидалось %v", order, want)
		}
	}
}

// Тумблеры 3.1 — must-match (RandomTrailers удлиняет handshake-пакеты, приёмник
// без него их не узнаёт), поэтому они обязаны доезжать до клиента как есть.
func TestBuildClientConfigV31(t *testing.T) {
	params := v3Params()
	params.AWGParams["RandomTrailers"] = "on"
	params.AWGParams["DisableCookies"] = "on"

	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params)
	for _, s := range []string{"RandomTrailers = on", "DisableCookies = on", "HeaderProtectionKey = "} {
		if !strings.Contains(conf, s) {
			t.Errorf("config missing: %s\n\nFull config:\n%s", s, conf)
		}
	}

	uri, _, err := BuildAmneziaVPNURI("clientPrivKey=", "clientPubKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "V31Server", "8.8.8.8", "8.8.4.4", params)
	if err != nil {
		t.Fatalf("BuildAmneziaVPNURI failed: %v", err)
	}
	awg := decodeVPNURI(t, uri).Containers[0].AWG
	if awg.ProtocolVersion != "3.1" {
		t.Errorf("expected protocol_version=3.1, got %s", awg.ProtocolVersion)
	}
	if awg.Params["RandomTrailers"] != "on" || awg.Params["DisableCookies"] != "on" {
		t.Errorf("тумблеры 3.1 не доехали до контейнера: %#v", awg.Params)
	}
}

func TestBuildAmneziaVPNURIv3(t *testing.T) {
	params := v3Params()

	uri, _, err := BuildAmneziaVPNURI("clientPrivKey=", "clientPubKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "V3Server", "8.8.8.8", "8.8.4.4", params)
	if err != nil {
		t.Fatalf("BuildAmneziaVPNURI failed: %v", err)
	}

	cfg := decodeVPNURI(t, uri)

	// Отдельного amnezia-awg3 в приложении AmneziaVPN нет: 3.0 отдаётся как awg2.
	if cfg.DefaultContainer != "amnezia-awg2" {
		t.Errorf("expected defaultContainer=amnezia-awg2, got %s", cfg.DefaultContainer)
	}
	if len(cfg.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(cfg.Containers))
	}
	awg := cfg.Containers[0].AWG
	// Для всей ветки 3.x приложение знает единственное значение protocol_version —
	// "3.1"; "2" оно считает устаревшим контейнером.
	if awg.ProtocolVersion != "3.1" {
		t.Errorf("expected protocol_version=3.1, got %s", awg.ProtocolVersion)
	}
	if awg.Params["HeaderProtectionKey"] != "aGVhZGVyS2V5MTIzNDU2Nzg5MA==" {
		t.Errorf("HeaderProtectionKey не доехал до контейнера: %q", awg.Params["HeaderProtectionKey"])
	}

	var lc map[string]interface{}
	if err := json.Unmarshal([]byte(awg.LastConfig), &lc); err != nil {
		t.Fatalf("last_config is not valid JSON: %v", err)
	}
	for _, key := range []string{"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "MaxHandshakeAttempts"} {
		if _, ok := lc[key]; !ok {
			t.Errorf("last_config не содержит %s", key)
		}
	}
	configStr, _ := lc["config"].(string)
	if !strings.Contains(configStr, "HeaderProtectionKey = ") {
		t.Error("last_config.config не содержит HeaderProtectionKey")
	}
}

// BuildAmneziaVPNURI не должна дописывать I1-I5 в params вызывающей стороны:
// пустой "I1 = " в клиентском .conf роняет awg-quick.
func TestBuildAmneziaVPNURINoMutation(t *testing.T) {
	params := &ServerParams{
		PublicKey:  "serverPubKey=",
		ListenPort: "51820",
		AWGParams: map[string]string{
			"Jc": "4", "S1": "52", "S2": "27", "S3": "45", "S4": "8",
			"H1": "1", "H2": "2", "H3": "3", "H4": "4",
		},
	}
	before := len(params.AWGParams)

	if _, _, err := BuildAmneziaVPNURI("priv=", "pub=", "psk=", "10.8.1.5", "1.2.3.4", "51820", "S", "8.8.8.8", "8.8.4.4", params); err != nil {
		t.Fatalf("BuildAmneziaVPNURI failed: %v", err)
	}

	if len(params.AWGParams) != before {
		t.Fatalf("params.AWGParams изменился: было %d ключей, стало %d (%v)", before, len(params.AWGParams), params.AWGParams)
	}
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if _, ok := params.AWGParams[k]; ok {
			t.Errorf("в params.AWGParams появился %s", k)
		}
	}

	// И клиентский конфиг, построенный ПОСЛЕ URI, не должен содержать пустых I1-I5.
	conf := BuildClientConfig("priv=", "psk=", "10.8.1.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params)
	if strings.Contains(conf, "I1 = \n") {
		t.Errorf("в клиентском конфиге пустой I1:\n%s", conf)
	}
}

// При отсутствии clientsTable таблица строится из [Peer]-секций.
func TestListClientsFromPeers(t *testing.T) {
	peers := []PeerBlock{
		{PublicKey: "AAA=", AllowedIPs: "10.8.1.2/32"},
		{PublicKey: "", AllowedIPs: "10.8.1.9/32"}, // битый блок — пропускаем
		{PublicKey: "BBB=", AllowedIPs: "10.8.1.3/32, fd00:a::3/128"},
	}

	clients := buildClientsFromPeers(peers)
	if len(clients) != 2 {
		t.Fatalf("ожидалось 2 клиента, получено %d", len(clients))
	}
	if clients[0].ClientID != "AAA=" || clients[0].UserData.ClientName != "peer-1" || clients[0].ID != 1 {
		t.Errorf("первый клиент разобран неверно: %+v", clients[0])
	}
	if clients[1].UserData.ClientName != "peer-2" || clients[1].ID != 2 {
		t.Errorf("нумерация сбилась на битом блоке: %+v", clients[1])
	}
	if clients[1].UserData.AllowedIPs != "10.8.1.3/32, fd00:a::3/128" {
		t.Errorf("AllowedIPs потерялись: %q", clients[1].UserData.AllowedIPs)
	}
	for _, c := range clients {
		if c.UserData.CreatorUID != 0 {
			t.Errorf("восстановленный ключ должен быть «ничьим» (creatorUid=0), получено %d", c.UserData.CreatorUID)
		}
	}

	if buildClientsFromPeers(nil) != nil {
		t.Error("nil peers → ожидался nil")
	}
}

func TestResolveClientDNS(t *testing.T) {
	tests := []struct {
		name   string
		srv    ServerConfig
		params *ServerParams
		want1  string
		want2  string
	}{
		{
			name:   "yaml перебивает конфиг сервера",
			srv:    ServerConfig{Mode: "native", DNS: "1.1.1.1, 1.0.0.1"},
			params: &ServerParams{DNS: "9.9.9.9"},
			want1:  "1.1.1.1", want2: "1.0.0.1",
		},
		{
			name:   "один адрес в yaml — второй фолбэк",
			srv:    ServerConfig{Mode: "native", DNS: "1.1.1.1"},
			params: nil,
			want1:  "1.1.1.1", want2: "8.8.4.4",
		},
		{
			name:   "DNS из [Interface] серверного конфига",
			srv:    ServerConfig{Mode: "native"},
			params: &ServerParams{DNS: "9.9.9.9, 149.112.112.112"},
			want1:  "9.9.9.9", want2: "149.112.112.112",
		},
		{
			name:   "ничего не задано — публичный фолбэк",
			srv:    ServerConfig{Mode: "native"},
			params: &ServerParams{},
			want1:  "8.8.8.8", want2: "8.8.4.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d1, d2 := resolveClientDNS(tt.srv, tt.params)
			if d1 != tt.want1 || d2 != tt.want2 {
				t.Errorf("resolveClientDNS = (%s, %s), ожидалось (%s, %s)", d1, d2, tt.want1, tt.want2)
			}
		})
	}
}

func TestIfaceNameDefault(t *testing.T) {
	if got := (ServerConfig{}).IfaceName(); got != "awg0" {
		t.Errorf("пустой Iface → ожидалось awg0, получено %s", got)
	}
	if got := (ServerConfig{Iface: "wg0"}).IfaceName(); got != "wg0" {
		t.Errorf("Iface=wg0 → ожидалось wg0, получено %s", got)
	}
}

// Два живых docker-сервера имеют пустой mode — смена дефолта их сломает.
func TestConfDirDefaults(t *testing.T) {
	if got := confDir(ServerConfig{}); got != defaultDockerDir {
		t.Errorf("Mode=\"\" должен означать docker: получено %s", got)
	}
	if got := confDir(ServerConfig{Mode: "docker"}); got != defaultDockerDir {
		t.Errorf("Mode=docker: получено %s", got)
	}
	if got := confDir(ServerConfig{Mode: "native"}); got != defaultNativeDir {
		t.Errorf("Mode=native: получено %s", got)
	}
	if got := confDir(ServerConfig{Mode: "native", AWGConfDir: "/etc/wireguard"}); got != "/etc/wireguard" {
		t.Errorf("явный awg_conf_dir: получено %s", got)
	}
	if got := confPath(ServerConfig{Mode: "native", Iface: "wg0"}); got != defaultNativeDir+"/wg0.conf" {
		t.Errorf("confPath с нестандартным интерфейсом: получено %s", got)
	}
}

// Предпочитается директория, где лежит и <iface>.conf, и clientsTable: иначе бот
// выберет /etc/wireguard без clientsTable и будет каждый раз восстанавливать
// таблицу из [Peer].
func TestPickAWGConf(t *testing.T) {
	cands := parseConfScan(
		"/etc/wireguard|wg0|no\n" +
			"/etc/amnezia/amneziawg|awg0|yes\n" +
			"\n")
	if len(cands) != 2 {
		t.Fatalf("parseConfScan вернул %d кандидатов: %+v", len(cands), cands)
	}

	best, ok := pickAWGConf(cands, []string{"awg0"})
	if !ok || best.Dir != "/etc/amnezia/amneziawg" || best.Iface != "awg0" {
		t.Errorf("ожидалась /etc/amnezia/amneziawg с awg0, получено %+v", best)
	}

	// Нет clientsTable нигде — берём поднятый интерфейс.
	onlyWG := parseConfScan("/etc/wireguard|wg0|no\n/etc/amnezia/amneziawg|awg0|no\n")
	best, ok = pickAWGConf(onlyWG, []string{"wg0"})
	if !ok || best.Iface != "wg0" {
		t.Errorf("ожидался поднятый wg0, получено %+v", best)
	}

	if _, ok := pickAWGConf(nil, nil); ok {
		t.Error("пустой список кандидатов → ожидалось false")
	}
}

func TestPickIface(t *testing.T) {
	if got := pickIface([]string{"wg0", "awg0"}, ""); got != "awg0" {
		t.Errorf("без предпочтения ожидался awg0, получено %s", got)
	}
	if got := pickIface([]string{"wg0", "awg0"}, "wg0"); got != "wg0" {
		t.Errorf("настроенный wg0 приоритетнее, получено %s", got)
	}
	if got := pickIface([]string{"wg1"}, ""); got != "wg1" {
		t.Errorf("единственный интерфейс должен выбираться, получено %s", got)
	}
	if got := pickIface(nil, "wg0"); got != "wg0" {
		t.Errorf("пустой список → сохраняем настроенный, получено %s", got)
	}
	if got := pickIface(nil, ""); got != "awg0" {
		t.Errorf("пустой список без предпочтения → awg0, получено %s", got)
	}
}

func TestDerivePublicKey(t *testing.T) {
	// Вектор проверен против `awg pubkey` на реальном сервере.
	const priv = "EIW3XjQle9t8v29XijOKQo2ZQxS2+Xxq6Hr51xu4cFI="
	const wantPub = "v54/dW01wtlvXJ51Qic9QYe4T2dZmyg96/WuLFCkcgU="

	pub, err := derivePublicKey(priv)
	if err != nil {
		t.Fatalf("derivePublicKey failed: %v", err)
	}
	if pub != wantPub {
		t.Errorf("derivePublicKey: ожидалось %s, получено %s", wantPub, pub)
	}

	// Лишние пробелы/перевод строки не должны ломать деривацию.
	pub2, err := derivePublicKey("  " + priv + "\n")
	if err != nil {
		t.Fatalf("derivePublicKey (с пробелами) failed: %v", err)
	}
	if pub2 != wantPub {
		t.Errorf("derivePublicKey (с пробелами): ожидалось %s, получено %s", wantPub, pub2)
	}

	// Невалидный/пустой ключ — ошибка, а не пустой публичный ключ.
	if _, err := derivePublicKey(""); err == nil {
		t.Error("ожидалась ошибка для пустого ключа")
	}
}

func TestEndpointHost(t *testing.T) {
	// Без endpoint_ip — используется IP (адрес SSH-подключения).
	s1 := ServerConfig{IP: "2a01:db8::1"}
	if got := s1.EndpointHost(); got != "2a01:db8::1" {
		t.Errorf("без EndpointIP: ожидалось 2a01:db8::1, получено %s", got)
	}
	// С endpoint_ip — в клиентский конфиг идёт он (IPv4), хотя SSH по IPv6.
	s2 := ServerConfig{IP: "2a01:db8::1", EndpointIP: "1.2.3.4"}
	if got := s2.EndpointHost(); got != "1.2.3.4" {
		t.Errorf("с EndpointIP: ожидалось 1.2.3.4, получено %s", got)
	}
}

// Удаление СРЕДНЕГО пира не должно ломать заголовок [Peer] у следующего.
func TestRemovePeerBlockMiddle(t *testing.T) {
	conf := `[Interface]
PrivateKey = serverPriv=
Address = 10.8.1.0/24
ListenPort = 51820

[Peer]
PublicKey = AAA=
PresharedKey = pskA=
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = BBB=
PresharedKey = pskB=
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = CCC=
PresharedKey = pskC=
AllowedIPs = 10.8.1.3/32
`
	out := removePeerBlock(conf, "BBB=")

	if strings.Contains(out, "BBB=") {
		t.Error("удалённый пир BBB всё ещё присутствует")
	}
	// Оба оставшихся пира должны сохранить заголовки [Peer].
	if n := strings.Count(out, "[Peer]"); n != 2 {
		t.Errorf("ожидалось 2 блока [Peer], получено %d\n%s", n, out)
	}
	for _, want := range []string{"AAA=", "CCC=", "10.8.1.1/32", "10.8.1.3/32"} {
		if !strings.Contains(out, want) {
			t.Errorf("в результате нет %q\n%s", want, out)
		}
	}
	// Каждый PublicKey должен предваряться [Peer].
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "PublicKey") {
			// найти ближайший непустой предыдущий значимый маркер — должен быть [Peer]
			seenPeer := false
			for j := i - 1; j >= 0; j-- {
				tj := strings.TrimSpace(lines[j])
				if tj == "[Peer]" {
					seenPeer = true
					break
				}
				if tj == "" {
					continue
				}
				break
			}
			if !seenPeer {
				t.Errorf("PublicKey без предшествующего [Peer] на строке %d\n%s", i, out)
			}
		}
	}
}

// Удаление последнего пира оставляет валидный конфиг.
func TestRemovePeerBlockLast(t *testing.T) {
	conf := `[Interface]
PrivateKey = serverPriv=
Address = 10.8.1.0/24

[Peer]
PublicKey = AAA=
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = BBB=
AllowedIPs = 10.8.1.2/32
`
	out := removePeerBlock(conf, "BBB=")
	if strings.Contains(out, "BBB=") {
		t.Error("удалённый пир BBB всё ещё присутствует")
	}
	if n := strings.Count(out, "[Peer]"); n != 1 {
		t.Errorf("ожидался 1 блок [Peer], получено %d\n%s", n, out)
	}
}

package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
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
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, fd00:awg::2/128"}},
		{UserData: ClientData{AllowedIPs: "10.8.0.3/32, fd00:awg::3/128"}},
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
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, fd00:awg::2/128"}},
		{UserData: ClientData{AllowedIPs: "10.8.0.3/32, fd00:awg::3/128"}},
	}

	alloc, err := allocateIPv6(clients, "fd00:awg::")
	if err != nil {
		t.Fatalf("allocateIPv6 failed: %v", err)
	}
	if alloc.ClientAddr != "fd00:awg::4" {
		t.Errorf("expected fd00:awg::4, got %s", alloc.ClientAddr)
	}
	if alloc.AllowedMask != 128 {
		t.Errorf("expected mask 128, got %d", alloc.AllowedMask)
	}
}

func TestAllocateIPv6Empty(t *testing.T) {
	alloc, err := allocateIPv6(nil, "fd00:awg::")
	if err != nil {
		t.Fatalf("allocateIPv6 failed: %v", err)
	}
	if alloc.ClientAddr != "fd00:awg::2" {
		t.Errorf("expected fd00:awg::2, got %s", alloc.ClientAddr)
	}
}

func TestAllocateIPv6Subnet112(t *testing.T) {
	// /96 pool → allocates /112 subnets per client
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.0.2/32, 2a01:db8::1:0/112"}},
	}

	alloc, err := allocateIPv6(clients, "2a01:db8::/96")
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
	alloc, err := allocateIPv6(nil, "2a01:db8::/96")
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

	alloc, err := allocateIPv6(clients, "2a01:db8::1:0/112")
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
	conf := buildServerConf("testPrivKey=", 51820, "eth0", params, "", "")
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
	confV6 := buildServerConf("testPrivKey=", 51820, "eth0", params, "fd00:awg::1/112", "fd00:awg::1/112")
	if !strings.Contains(confV6, "fd00:awg::1/112") {
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
	confV6_64 := buildServerConf("testPrivKey=", 51820, "eth0", params, "2a01:db8::1/64", "2a01:db8::4000/114")
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
			wantIfaceAddr:    "fd00:awg::1/112",
			wantClientSubnet: "fd00:awg::1/112",
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

	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.0.5", "1.2.3.4", "51820", "8.8.8.8", "8.8.4.4", params, "fd00:awg::5")

	if !strings.Contains(conf, "Address = 10.8.0.5/32, fd00:awg::5/128") {
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

	// Decode: strip prefix → base64url decode → skip 4-byte Qt header → zlib decompress → JSON
	encoded := uri[len("vpn://"):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	// Skip Qt qCompress 4-byte big-endian size header
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
	if awg.Jc != "4" {
		t.Errorf("expected Jc=4, got %s", awg.Jc)
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

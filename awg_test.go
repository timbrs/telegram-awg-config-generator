package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"io"
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

	ip, err := allocateIP(clients)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.1.4" {
		t.Errorf("expected 10.8.1.4, got %s", ip)
	}
}

func TestAllocateIPEmpty(t *testing.T) {
	ip, err := allocateIP(nil)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.1.2" {
		t.Errorf("expected 10.8.1.2, got %s", ip)
	}
}

func TestAllocateIPGap(t *testing.T) {
	clients := []ClientEntry{
		{UserData: ClientData{AllowedIPs: "10.8.1.2/32"}},
		{UserData: ClientData{AllowedIPs: "10.8.1.4/32"}},
	}

	ip, err := allocateIP(clients)
	if err != nil {
		t.Fatalf("allocateIP failed: %v", err)
	}
	if ip != "10.8.1.3" {
		t.Errorf("expected 10.8.1.3 (gap fill), got %s", ip)
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

	conf := BuildClientConfig("clientPrivKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", params)

	mustContain := []string{
		"[Interface]",
		"PrivateKey = clientPrivKey=",
		"Address = 10.8.1.5/32",
		"DNS = 1.1.1.1",
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

	uri, _, err := BuildAmneziaVPNURI("clientPrivKey=", "clientPubKey=", "pskKey=", "10.8.1.5", "1.2.3.4", "51820", "TestServer", params)
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
	if cfg.DNS1 != "1.1.1.1" {
		t.Errorf("expected dns1=1.1.1.1, got %s", cfg.DNS1)
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

package main

import (
	"encoding/json"
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

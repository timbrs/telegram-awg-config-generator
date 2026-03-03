package main

import (
	"os"
	"testing"
)

func TestConfigLoad(t *testing.T) {
	yaml := `bot_token: "test-token"
servers:
  - name: "srv1"
    ip: "1.2.3.4"
    login: "root"
    pass: "secret"
    allowed_uids: [111, 222]
  - name: "srv2"
    ip: "5.6.7.8"
    login: "admin"
    pass: "pass2"
    allowed_uids: [222, 333]
`
	tmp, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	cm := NewConfigManager(tmp.Name())
	if err := cm.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	cfg := cm.Get()
	if cfg.BotToken != "test-token" {
		t.Errorf("expected token 'test-token', got '%s'", cfg.BotToken)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "srv1" {
		t.Errorf("expected server name 'srv1', got '%s'", cfg.Servers[0].Name)
	}
}

func TestServersForUser(t *testing.T) {
	yaml := `bot_token: "t"
servers:
  - name: "s1"
    ip: "1.1.1.1"
    login: "r"
    pass: "p"
    allowed_uids: [111, 222]
  - name: "s2"
    ip: "2.2.2.2"
    login: "r"
    pass: "p"
    allowed_uids: [222, 333]
`
	tmp, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(yaml)
	tmp.Close()

	cm := NewConfigManager(tmp.Name())
	cm.Load()

	tests := []struct {
		uid      int64
		expected int
	}{
		{111, 1},
		{222, 2},
		{333, 1},
		{999, 0},
	}

	for _, tt := range tests {
		indices := cm.ServersForUser(tt.uid)
		if len(indices) != tt.expected {
			t.Errorf("uid %d: expected %d servers, got %d", tt.uid, tt.expected, len(indices))
		}
	}
}

func TestCheckReload(t *testing.T) {
	yaml1 := `bot_token: "token1"
servers: []
`
	tmp, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(yaml1)
	tmp.Close()

	cm := NewConfigManager(tmp.Name())
	cm.Load()

	if cm.Get().BotToken != "token1" {
		t.Fatal("expected token1")
	}

	// Overwrite with new content
	yaml2 := `bot_token: "token2"
servers: []
`
	os.WriteFile(tmp.Name(), []byte(yaml2), 0644)

	if err := cm.CheckReload(); err != nil {
		t.Fatalf("CheckReload failed: %v", err)
	}

	if cm.Get().BotToken != "token2" {
		t.Errorf("expected token2 after reload, got '%s'", cm.Get().BotToken)
	}
}

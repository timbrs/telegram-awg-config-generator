package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// saveLocked перезаписывает весь YAML при любом изменении, поэтому новые поля
// обязаны быть omitempty: иначе в записи живых серверов насыплется awg_version: 0.
func TestServerConfigYAMLOmitEmpty(t *testing.T) {
	cfg := AppConfig{
		BotToken: "t",
		Servers: []ServerConfig{{
			Name: "srv1", IP: "1.2.3.4", Login: "root", Pass: "p",
			AllowedUIDs: []int64{111},
		}},
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	out := string(data)

	for _, key := range []string{"iface:", "awg_version:", "awg_tools_version:", "dns:", "mode:", "awg_conf_dir:"} {
		if strings.Contains(out, key) {
			t.Errorf("пустое поле %q не должно попадать в YAML:\n%s", key, out)
		}
	}
}

func TestServerConfigYAMLRoundTrip(t *testing.T) {
	orig := AppConfig{
		BotToken: "t",
		Servers: []ServerConfig{{
			Name: "srv1", IP: "1.2.3.4", Login: "root", Pass: "p",
			AllowedUIDs: []int64{111},
			Mode:        "native",
			Iface:       "wg0",
			AWGVersion:  int(AWGVersion3),
			AWGToolsVer: "3.0.20260730",
			DNS:         "1.1.1.1, 1.0.0.1",
		}},
	}

	data, err := yaml.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var back AppConfig
	if err := yaml.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	got := back.Servers[0]
	if got.Iface != "wg0" || got.IfaceName() != "wg0" {
		t.Errorf("Iface не пережил round-trip: %q", got.Iface)
	}
	if got.ProtoVersion() != AWGVersion3 {
		t.Errorf("AWGVersion не пережил round-trip: %v", got.ProtoVersion())
	}
	if got.AWGToolsVer != "3.0.20260730" {
		t.Errorf("AWGToolsVer не пережил round-trip: %q", got.AWGToolsVer)
	}
	if got.DNS != "1.1.1.1, 1.0.0.1" {
		t.Errorf("DNS не пережил round-trip: %q", got.DNS)
	}
}

// Get() обязан отдавать независимую копию: вызывающие держат сервер по указателю
// (resolveServer) и читают его без блокировки, пока мутаторы правят элементы
// среза на месте.
func TestGetReturnsIndependentCopy(t *testing.T) {
	tmp, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("bot_token: \"t\"\nservers:\n  - name: \"s1\"\n    ip: \"1.1.1.1\"\n    login: \"r\"\n    pass: \"p\"\n    allowed_uids: [111]\n    report_uids: [111]\n")
	tmp.Close()

	cm := NewConfigManager(tmp.Name())
	if err := cm.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	snapshot := cm.Get()
	if err := cm.RenameServer(0, "renamed"); err != nil {
		t.Fatalf("RenameServer failed: %v", err)
	}
	if err := cm.AddAllowedUID(0, 222); err != nil {
		t.Fatalf("AddAllowedUID failed: %v", err)
	}

	if snapshot.Servers[0].Name != "s1" {
		t.Errorf("ранее полученная копия изменилась: %s", snapshot.Servers[0].Name)
	}
	if len(snapshot.Servers[0].AllowedUIDs) != 1 {
		t.Errorf("срез allowed_uids разделяется с менеджером: %v", snapshot.Servers[0].AllowedUIDs)
	}

	// Правка копии не должна доезжать до менеджера.
	snapshot.Servers[0].Name = "hacked"
	snapshot.Servers[0].ReportUIDs[0] = 999
	fresh := cm.Get()
	if fresh.Servers[0].Name != "renamed" || fresh.Servers[0].ReportUIDs[0] != 111 {
		t.Errorf("правка копии просочилась в конфиг: %+v", fresh.Servers[0])
	}
}

// SetAWGInfo пишет версию и интерфейс в config.yaml; дефолтный awg0 не пишется.
func TestSetAWGInfo(t *testing.T) {
	tmp, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString("bot_token: \"t\"\nservers:\n  - name: \"s1\"\n    ip: \"1.1.1.1\"\n    login: \"r\"\n    pass: \"p\"\n    allowed_uids: [111]\n")
	tmp.Close()

	cm := NewConfigManager(tmp.Name())
	if err := cm.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	info := AWGVersionInfo{Version: AWGVersion3, ToolsRaw: "3.0.20260730", KmodRaw: "3.0.20260731-04"}
	if err := cm.SetAWGInfo(0, info, "wg0"); err != nil {
		t.Fatalf("SetAWGInfo failed: %v", err)
	}

	srv := cm.Get().Servers[0]
	if srv.ProtoVersion() != AWGVersion3 || srv.Iface != "wg0" || srv.AWGToolsVer != "3.0.20260730" {
		t.Errorf("SetAWGInfo не сохранил данные: %+v", srv)
	}

	// Дефолтный интерфейс не должен попадать в YAML.
	if err := cm.SetAWGInfo(0, info, defaultIfaceName); err != nil {
		t.Fatalf("SetAWGInfo failed: %v", err)
	}
	if got := cm.Get().Servers[0]; got.Iface != "" || got.IfaceName() != defaultIfaceName {
		t.Errorf("awg0 должен сбрасывать iface в пустую строку, получено %q", got.Iface)
	}

	if err := cm.SetAWGInfo(99, info, ""); err == nil {
		t.Error("индекс вне диапазона должен давать ошибку")
	}
}

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

// Создатель сервера должен быть суперадмином: иначе отчёты по серверу не
// приходят никому, а ключи других админов не видит даже владелец.
func TestEnsureCreatorIsSuperAdmin(t *testing.T) {
	servers := []ServerConfig{
		{Name: "пустой report_uids", AllowedUIDs: []int64{100, 200}},
		{Name: "суперадмин уже есть", AllowedUIDs: []int64{100, 200}, ReportUIDs: []int64{200}},
		{Name: "без админов вовсе"},
	}

	if !ensureCreatorIsSuperAdmin(servers) {
		t.Fatal("ожидалось изменение: у первого сервера пустой report_uids")
	}

	if len(servers[0].ReportUIDs) != 1 || servers[0].ReportUIDs[0] != 100 {
		t.Errorf("создатель не попал в report_uids: %v", servers[0].ReportUIDs)
	}
	// Снятого вручную суперадмина возвращать нельзя — иначе настройку не отменить.
	if len(servers[1].ReportUIDs) != 1 || servers[1].ReportUIDs[0] != 200 {
		t.Errorf("существующий список суперадминов изменён: %v", servers[1].ReportUIDs)
	}
	if len(servers[2].ReportUIDs) != 0 {
		t.Errorf("серверу без админов суперадмин взяться неоткуда: %v", servers[2].ReportUIDs)
	}

	// Повторный проход ничего не меняет.
	if ensureCreatorIsSuperAdmin(servers) {
		t.Error("второй проход не должен ничего менять")
	}
}

// Миграция должна доезжать до файла: иначе она повторялась бы при каждом старте.
func TestLoadWritesCreatorToReportUIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "bot_token: \"t\"\nservers:\n  - name: s1\n    ip: 1.2.3.4\n    login: root\n    pass: p\n    allowed_uids: [111, 222]\n    report_uids: []\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cm := NewConfigManager(path)
	if err := cm.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cm.Get().Servers[0].ReportUIDs; len(got) != 1 || got[0] != 111 {
		t.Fatalf("report_uids после загрузки = %v", got)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "111") {
		t.Errorf("создатель не сохранён в файл:\n%s", saved)
	}

	// Файл переписан ботом — CheckReload не должен считать это внешней правкой
	// и уходить на второй круг.
	if err := cm.CheckReload(); err != nil {
		t.Errorf("CheckReload после миграции: %v", err)
	}
}

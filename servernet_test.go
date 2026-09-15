package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Настройки сервера меняет создатель (первый в allowed_uids) или суперадмин.
// От canManageReports отличие в том, что создатель не теряет право с появлением
// суперадминов.
func TestCanManageServer(t *testing.T) {
	srv := ServerConfig{
		AllowedUIDs: []int64{100, 200, 300},
		ReportUIDs:  []int64{300},
	}

	if !canManageServer(100, srv) {
		t.Error("создатель сервера должен управлять настройками")
	}
	if !canManageServer(300, srv) {
		t.Error("суперадмин должен управлять настройками")
	}
	if canManageServer(200, srv) {
		t.Error("обычный админ не должен управлять настройками")
	}
	if canManageServer(999, srv) {
		t.Error("посторонний не должен управлять настройками")
	}

	// В отличие от прав на report_uids, создатель остаётся при своих даже когда
	// суперадмины уже назначены.
	if canManageReports(100, srv) {
		t.Error("предполагалось, что право на report_uids у создателя пропадает — проверка потеряла смысл")
	}

	if canManageServer(100, ServerConfig{}) {
		t.Error("у сервера без админов управлять нечем")
	}
}

func TestEndpointHostAndSSHHosts(t *testing.T) {
	v4only := ServerConfig{IP: "1.2.3.4"}
	if got := v4only.EndpointHost(); got != "1.2.3.4" {
		t.Errorf("EndpointHost = %q", got)
	}
	if got := v4only.SSHHosts(); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("SSHHosts = %v", got)
	}

	dual := ServerConfig{IP: "1.2.3.4", IPv6Host: "2a01:db8::1"}
	if got := dual.EndpointHost(); got != "1.2.3.4" {
		t.Errorf("без предпочтения Endpoint должен остаться на IPv4, получено %q", got)
	}
	// IPv6 всё равно годится как запасной адрес для SSH.
	if got := dual.SSHHosts(); len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "2a01:db8::1" {
		t.Errorf("SSHHosts = %v", got)
	}

	// IPv6 и prefer — это ТОЛЬКО про SSH бота. Ключи выдаются по IPv4.
	dual.Prefer = preferIPv6
	if got := dual.SSHHosts(); len(got) != 2 || got[0] != "2a01:db8::1" || got[1] != "1.2.3.4" {
		t.Errorf("с prefer=ipv6 порядок адресов должен смениться: %v", got)
	}
	if got := dual.EndpointHost(); got != "1.2.3.4" {
		t.Errorf("Endpoint ключей обязан остаться IPv4 даже при prefer=ipv6, получено %q", got)
	}

	// Предпочтение без адреса ничего не меняет.
	noAddr := ServerConfig{IP: "1.2.3.4", Prefer: preferIPv6}
	if noAddr.PrefersIPv6() {
		t.Error("prefer=ipv6 без адреса не должен считаться выбором IPv6")
	}
	if got := noAddr.SSHHosts(); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("SSHHosts без IPv6-адреса = %v", got)
	}

	// EndpointIP (публичный IPv4 при SSH по другому адресу) продолжает работать.
	behindNAT := ServerConfig{IP: "10.0.0.5", EndpointIP: "1.2.3.4", IPv6Host: "2a01:db8::1", Prefer: preferIPv6}
	if got := behindNAT.EndpointHost(); got != "1.2.3.4" {
		t.Errorf("EndpointIP должен иметь приоритет над IP, получено %q", got)
	}
}

func TestSetServerNet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("bot_token: \"t\"\nservers:\n  - name: s1\n    ip: 1.2.3.4\n    login: root\n    pass: p\n    allowed_uids: [1]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cm := NewConfigManager(path)
	if err := cm.Load(); err != nil {
		t.Fatal(err)
	}

	if err := cm.SetServerNet(0, "2a01:db8::1", preferIPv6); err != nil {
		t.Fatalf("SetServerNet: %v", err)
	}
	srv := cm.Get().Servers[0]
	if srv.IPv6Host != "2a01:db8::1" || srv.Prefer != preferIPv6 {
		t.Errorf("сохранено %q / %q", srv.IPv6Host, srv.Prefer)
	}

	// IPv4 — значение по умолчанию, в YAML его писать незачем.
	if err := cm.SetServerNet(0, "2a01:db8::1", preferIPv4); err != nil {
		t.Fatalf("SetServerNet: %v", err)
	}
	if got := cm.Get().Servers[0].Prefer; got != "" {
		t.Errorf("prefer=ipv4 должен храниться как пустое значение, получено %q", got)
	}

	// Снятый адрес не должен оставлять предпочтение, которое некуда применить.
	if err := cm.SetServerNet(0, "", preferIPv6); err != nil {
		t.Fatalf("SetServerNet: %v", err)
	}
	srv = cm.Get().Servers[0]
	if srv.IPv6Host != "" || srv.Prefer != "" {
		t.Errorf("после удаления адреса осталось %q / %q", srv.IPv6Host, srv.Prefer)
	}

	if err := cm.SetServerNet(0, "2a01:db8::1", "мусор"); err == nil {
		t.Error("неизвестное предпочтение должно отвергаться")
	}
	if err := cm.SetServerNet(5, "", ""); err == nil {
		t.Error("индекс вне диапазона должен отвергаться")
	}
}

func TestIPFamilyLabel(t *testing.T) {
	tests := []struct{ host, want string }{
		{"1.2.3.4", "IPv4"},
		{"2a01:db8::1", "IPv6"},
		{"[2a01:db8::1]", "IPv6"},
		{"vpn.example.com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := ipFamilyLabel(tt.host); got != tt.want {
			t.Errorf("ipFamilyLabel(%q) = %q, ожидалось %q", tt.host, got, tt.want)
		}
	}

	if got := hostWithFamily("1.2.3.4"); got != "1.2.3.4 (IPv4)" {
		t.Errorf("hostWithFamily = %q", got)
	}
	if got := hostWithFamily("vpn.example.com"); got != "vpn.example.com" {
		t.Errorf("для DNS-имени семейство не приписываем: %q", got)
	}
}

// Строка статуса должна показывать адрес, по которому запрос УШЁЛ, а не тот,
// что выбран в настройках: из-за фолбэка в sshDial это могут быть разные адреса.
func TestSSHInfoLine(t *testing.T) {
	srv := ServerConfig{Name: "ssh-info-test", IP: "1.2.3.4", IPv6Host: "2a01:db8::1", Prefer: preferIPv6}

	if got := sshInfoLine(srv); !strings.Contains(got, "подключений ещё не было") {
		t.Errorf("до первого подключения ожидалась пометка об этом: %q", got)
	}

	noteSSHHost(srv, "2a01:db8::1")
	got := sshInfoLine(srv)
	if !strings.Contains(got, "2a01:db8::1 (IPv6)") {
		t.Errorf("sshInfoLine = %q", got)
	}
	if strings.Contains(got, "запасной") {
		t.Errorf("подключение по предпочитаемому адресу не должно помечаться запасным: %q", got)
	}

	// Сработал фолбэк: соединение ушло по IPv4, хотя выбран IPv6.
	noteSSHHost(srv, "1.2.3.4")
	got = sshInfoLine(srv)
	if !strings.Contains(got, "1.2.3.4 (IPv4)") || !strings.Contains(got, "запасной") {
		t.Errorf("фолбэк должен быть виден в строке: %q", got)
	}
	if !strings.Contains(got, "2a01:db8::1 (IPv6) не ответил") {
		t.Errorf("в строке должен быть назван недоступный адрес: %q", got)
	}
}

func TestSSHHostPreferred(t *testing.T) {
	if got := (ServerConfig{IP: "1.2.3.4"}).SSHHost(); got != "1.2.3.4" {
		t.Errorf("SSHHost = %q", got)
	}
	dual := ServerConfig{IP: "1.2.3.4", IPv6Host: "2a01:db8::1", Prefer: preferIPv6}
	if got := dual.SSHHost(); got != "2a01:db8::1" {
		t.Errorf("с prefer=ipv6 ожидался IPv6-адрес, получено %q", got)
	}
	if got := (ServerConfig{}).SSHHost(); got != "" {
		t.Errorf("у сервера без адресов SSHHost = %q", got)
	}
}

// preferOnly убирает запасной адрес: проверка доступности должна идти именно по
// выбранному протоколу, иначе SSH молча уйдёт на фолбэк и «проверка» соврёт.
func TestPreferOnly(t *testing.T) {
	srv := ServerConfig{IP: "1.2.3.4", IPv6Host: "2a01:db8::1", Prefer: preferIPv6}

	v6 := preferOnly(srv, preferIPv6)
	if got := v6.SSHHosts(); len(got) != 1 || got[0] != "2a01:db8::1" {
		t.Errorf("для проверки IPv6 ожидался единственный адрес IPv6, получено %v", got)
	}

	v4 := preferOnly(srv, preferIPv4)
	if got := v4.SSHHosts(); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("для проверки IPv4 ожидался единственный адрес IPv4, получено %v", got)
	}
}

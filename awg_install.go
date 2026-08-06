package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// InstallStep represents a single step in the AWG installation process.
type InstallStep struct {
	StepName string
	Command  string
	Output   string
	Success  bool
	Error    string
	Duration time.Duration
	Rollback bool // true if this is a rollback step
}

// InstallLog tracks all steps of an AWG installation.
type InstallLog struct {
	Steps       []InstallStep
	ServerIP    string
	StartedAt   time.Time
	FinishedAt  time.Time
	FinalStatus string // "success" / "failed" / "rolled_back"
}

func (l *InstallLog) AddStep(name, cmd, output string, success bool, err error, dur time.Duration) {
	step := InstallStep{
		StepName: name,
		Command:  cmd,
		Output:   truncate(output, 2000),
		Success:  success,
		Duration: dur,
	}
	if err != nil {
		step.Error = err.Error()
	}
	l.Steps = append(l.Steps, step)
}

func (l *InstallLog) AddRollbackStep(name, cmd, output string, success bool, err error, dur time.Duration) {
	step := InstallStep{
		StepName: name,
		Command:  cmd,
		Output:   truncate(output, 2000),
		Success:  success,
		Duration: dur,
		Rollback: true,
	}
	if err != nil {
		step.Error = err.Error()
	}
	l.Steps = append(l.Steps, step)
}

func (l *InstallLog) String() string {
	var sb strings.Builder
	sb.WriteString("=== AWG Install Log ===\n")
	sb.WriteString(fmt.Sprintf("Server: %s\n", l.ServerIP))
	sb.WriteString(fmt.Sprintf("Started: %s\n", l.StartedAt.Format("2006-01-02 15:04:05")))
	if !l.FinishedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("Finished: %s\n", l.FinishedAt.Format("2006-01-02 15:04:05")))
	}
	sb.WriteString(fmt.Sprintf("Status: %s\n\n", l.FinalStatus))

	for i, step := range l.Steps {
		if step.Rollback {
			if i > 0 && !l.Steps[i-1].Rollback {
				sb.WriteString("\n=== Rollback ===\n")
			}
		}

		status := "[OK]"
		if !step.Success {
			status = "[FAIL]"
		}
		prefix := fmt.Sprintf("Step %d", i+1)
		if step.Rollback {
			prefix = "Rollback"
		}
		sb.WriteString(fmt.Sprintf("%s %s: %s (%.1fs)\n", status, prefix, step.StepName, step.Duration.Seconds()))
		if step.Command != "" {
			sb.WriteString(fmt.Sprintf("  $ %s\n", step.Command))
		}
		if step.Output != "" {
			for _, line := range strings.Split(strings.TrimSpace(step.Output), "\n") {
				sb.WriteString(fmt.Sprintf("  > %s\n", line))
			}
		}
		if step.Error != "" {
			sb.WriteString(fmt.Sprintf("  Error: %s\n", step.Error))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (l *InstallLog) LastError() string {
	for i := len(l.Steps) - 1; i >= 0; i-- {
		if !l.Steps[i].Success && !l.Steps[i].Rollback && l.Steps[i].Error != "" {
			return l.Steps[i].Error
		}
	}
	return "неизвестная ошибка"
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

// ServerDiag holds diagnostic info about the server.
type ServerDiag struct {
	OS         string // "ubuntu" / "debian"
	Codename   string // "jammy" / "bookworm"
	Arch       string // "x86_64" / "aarch64"
	NetIface   string // "eth0"
	IPv6Addr   string // "2a01:db8::1"
	IPv6Prefix int    // 48, 56, 64
	HasIPv6    bool
}

func runInstallStep(log *InstallLog, srv ServerConfig, name, cmd string, timeout time.Duration) (string, error) {
	start := time.Now()
	output, err := SSHRunTimeout(srv, cmd, timeout)
	dur := time.Since(start)
	log.AddStep(name, cmd, output, err == nil, err, dur)
	return output, err
}

func diagnoseServer(srv ServerConfig, log *InstallLog) (*ServerDiag, error) {
	diag := &ServerDiag{}

	// OS detection
	out, err := runInstallStep(log, srv, "Detect OS", "cat /etc/os-release", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("не удалось определить ОС: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			diag.OS = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_CODENAME=") {
			diag.Codename = strings.Trim(strings.TrimPrefix(line, "VERSION_CODENAME="), "\"")
		}
	}
	if diag.OS == "" {
		return nil, fmt.Errorf("не удалось определить ID ОС из /etc/os-release")
	}
	if diag.OS != "ubuntu" && diag.OS != "debian" {
		return nil, fmt.Errorf("неподдерживаемая ОС: %s (поддерживаются ubuntu и debian)", diag.OS)
	}

	// Architecture
	out, err = runInstallStep(log, srv, "Detect arch", "uname -m", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("не удалось определить архитектуру: %w", err)
	}
	diag.Arch = strings.TrimSpace(out)

	// Network interface
	out, err = runInstallStep(log, srv, "Detect network interface", "ip route show default", 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("не удалось определить сетевой интерфейс: %w", err)
	}
	// Parse: "default via X.X.X.X dev eth0 ..."
	for _, field := range strings.Fields(out) {
		if diag.NetIface != "" {
			break
		}
		if field == "dev" {
			continue
		}
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			diag.NetIface = fields[i+1]
			break
		}
	}
	if diag.NetIface == "" {
		diag.NetIface = "eth0"
	}

	// IPv6 detection
	out, err = runInstallStep(log, srv, "Detect IPv6", "ip -6 addr show scope global", 10*time.Second)
	if err == nil && strings.Contains(out, "inet6") {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "inet6 ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					addrCIDR := parts[1] // e.g. "2a01:db8::1/48"
					ip, ipNet, parseErr := net.ParseCIDR(addrCIDR)
					if parseErr == nil {
						diag.IPv6Addr = ip.String()
						ones, _ := ipNet.Mask.Size()
						diag.IPv6Prefix = ones
						diag.HasIPv6 = true
					}
					break
				}
			}
		}
	}

	return diag, nil
}

func generateAWGParams() map[string]string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return map[string]string{
		"Jc":   fmt.Sprintf("%d", 3+r.Intn(6)),    // 3-8
		"Jmin": fmt.Sprintf("%d", 40+r.Intn(41)),  // 40-80
		"Jmax": fmt.Sprintf("%d", 80+r.Intn(41)),  // 80-120
		"S1":   fmt.Sprintf("%d", 15+r.Intn(136)), // 15-150
		"S2":   fmt.Sprintf("%d", 15+r.Intn(136)), // 15-150
		"S3":   fmt.Sprintf("%d", 15+r.Intn(136)), // 15-150 (handshake only)
		"S4":   fmt.Sprintf("%d", 4+r.Intn(9)),    // 4-12 (data packets, MUST fit in MTU)
		"H1":   fmt.Sprintf("%d", r.Uint32()),
		"H2":   fmt.Sprintf("%d", r.Uint32()),
		"H3":   fmt.Sprintf("%d", r.Uint32()),
		"H4":   fmt.Sprintf("%d", r.Uint32()),
	}
}

// buildServerConf собирает awg0.conf для установки с нуля. v — версия протокола
// на сервере: параметры, которых в ней нет, в конфиг не попадают.
func buildServerConf(privKey string, port int, netIface string, awgParams map[string]string, ipv6IfaceAddr, ipv6ClientSubnet string, v AWGVersion) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))

	addr := "10.8.0.1/22"
	if ipv6IfaceAddr != "" {
		addr += ", " + ipv6IfaceAddr
	}
	sb.WriteString(fmt.Sprintf("Address = %s\n", addr))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", port))

	// AWG params — только те, что понимает версия v на сервере.
	for _, key := range serverParamOrder(v) {
		if val, ok := awgParams[key]; ok {
			sb.WriteString(fmt.Sprintf("%s = %s\n", key, val))
		}
	}

	// PostUp — idempotent: check with -C before adding with -A
	postUp := fmt.Sprintf(
		"iptables -C FORWARD -i %%i -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %%i -j ACCEPT; "+
			"iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -j MASQUERADE",
		netIface, netIface)
	if ipv6IfaceAddr != "" {
		postUp += "; sysctl -q -w net.ipv6.conf.all.forwarding=1"
		postUp += fmt.Sprintf(
			"; ip6tables -C FORWARD -i %%i -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -i %%i -j ACCEPT" +
				"; ip6tables -C FORWARD -o %%i -j ACCEPT 2>/dev/null || ip6tables -A FORWARD -o %%i -j ACCEPT")
		// Add explicit route for client subnet if it differs from iface addr (the /64 case)
		if ipv6ClientSubnet != "" && ipv6ClientSubnet != ipv6IfaceAddr {
			postUp += fmt.Sprintf("; ip -6 route add %s dev %%i 2>/dev/null || ip -6 route replace %s dev %%i",
				ipv6ClientSubnet, ipv6ClientSubnet)
		}
	}
	sb.WriteString(fmt.Sprintf("PostUp = %s\n", postUp))

	// PostDown
	postDown := fmt.Sprintf(
		"iptables -D FORWARD -i %%i -j ACCEPT 2>/dev/null; "+
			"iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null",
		netIface)
	if ipv6IfaceAddr != "" {
		postDown += "; ip6tables -D FORWARD -i %i -j ACCEPT 2>/dev/null"
		postDown += "; ip6tables -D FORWARD -o %i -j ACCEPT 2>/dev/null"
		if ipv6ClientSubnet != "" && ipv6ClientSubnet != ipv6IfaceAddr {
			postDown += fmt.Sprintf("; ip -6 route del %s dev %%i 2>/dev/null", ipv6ClientSubnet)
		}
	}
	sb.WriteString(fmt.Sprintf("PostDown = %s\n", postDown))

	return sb.String()
}

// calculateVPNv6Subnet computes IPv6 addressing for the AWG VPN.
// Returns:
//   - ifaceAddr: address for [Interface] Address line (e.g. "2a01:db8::1/64")
//   - clientSubnet: CIDR for client allocation and routing (e.g. "2a01:db8::4000/114")
//   - serverIP: bare server IP without mask (e.g. "2a01:db8::1")
//
// For /64 prefixes (most common): uses prefix::4000/114 (16384 addresses) within the /64,
// with an explicit route and ndppd required.
// For /48-/56: uses a separate /112 in a different /64 — no overlap, no ndppd needed.
func calculateVPNv6Subnet(serverIPv6 string, prefixLen int) (ifaceAddr, clientSubnet, serverIP string) {
	ip := net.ParseIP(serverIPv6)
	if ip == nil {
		return "fd00:awg::1/112", "fd00:awg::1/112", "fd00:awg::1"
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return "fd00:awg::1/112", "fd00:awg::1/112", "fd00:awg::1"
	}

	switch {
	case prefixLen <= 48:
		// Use prefix:0001::1/112 — separate /64, no overlap with eth0
		result := make(net.IP, 16)
		copy(result, ip16[:6]) // copy first 48 bits
		result[7] = 1          // set subnet ID to 1 in bytes 6-7 (bits 48-63)
		result[15] = 1         // ::1
		subnet := fmt.Sprintf("%s/112", result)
		return subnet, subnet, result.String()

	case prefixLen <= 56:
		// Use prefix + next /64 subnet — separate /64, no overlap
		result := make(net.IP, 16)
		copy(result, ip16[:7])  // copy first 56 bits
		result[7] = ip16[7] + 1 // next subnet
		result[15] = 1          // ::1
		subnet := fmt.Sprintf("%s/112", result)
		return subnet, subnet, result.String()

	case prefixLen <= 64:
		// /64 — most common VPS case.
		// Server gets prefix::1/64 on AWG interface.
		// Each client gets a /112 subnet: prefix::1:0/112, prefix::2:0/112, etc.
		// This gives each client 65536 addresses — nice for routers (MikroTik).
		// ndppd proxies prefix::/96 to cover all client subnets.
		// Requires explicit route + ndppd because it's within the same /64 as eth0.
		srvResult := make(net.IP, 16)
		copy(srvResult, ip16[:8]) // copy the /64 prefix
		srvResult[15] = 1         // ::1
		ifAddr := fmt.Sprintf("%s/64", srvResult)

		// Client subnet template: prefix::/96 covers all /112 sub-subnets
		clientBase := make(net.IP, 16)
		copy(clientBase, ip16[:8])
		cSubnet := fmt.Sprintf("%s/96", clientBase)

		return ifAddr, cSubnet, srvResult.String()

	default:
		// Prefix longer than /64 — use ULA
		return "fd00:awg::1/112", "fd00:awg::1/112", "fd00:awg::1"
	}
}

// needsNdppd returns true when the VPN IPv6 subnet is within the server's /64
// (ifaceAddr and clientSubnet differ), requiring NDP proxy for return traffic.
func needsNdppd(ipv6IfaceAddr, ipv6ClientSubnet string) bool {
	return ipv6IfaceAddr != "" && ipv6ClientSubnet != "" && ipv6IfaceAddr != ipv6ClientSubnet
}

// InstallAWGNative installs AmneziaWG natively on the server.
func InstallAWGNative(srv ServerConfig, port int, enableIPv6 bool, ipv6IfaceAddr, ipv6ClientSubnet string, progressFn func(string)) (*InstallLog, *ServerDiag, error) {
	log := &InstallLog{
		ServerIP:  srv.IP,
		StartedAt: time.Now(),
	}

	if port == 0 {
		port = 51820
	}

	// Step 1: Diagnose server
	progressFn("Шаг 1/13: Диагностика сервера...")
	diag, err := diagnoseServer(srv, log)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, nil, err
	}

	// Override net iface from config if set
	if srv.NetIface != "" {
		diag.NetIface = srv.NetIface
	}

	// Step 2: Install prerequisites
	progressFn("Шаг 2/13: Установка prerequisites...")
	_, err = runInstallStep(log, srv, "Install prerequisites",
		"DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common", 3*time.Minute)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("установка prerequisites: %w", err)
	}

	// Step 3: Add PPA/repository
	progressFn("Шаг 3/13: Добавление репозитория AWG...")
	if diag.OS == "ubuntu" {
		_, err = runInstallStep(log, srv, "Add PPA",
			"add-apt-repository -y ppa:amnezia/ppa", 2*time.Minute)
	} else {
		// Debian
		debCmd := `bash -c 'apt-get install -y curl gnupg && curl -fsSL https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/jammy/Release.gpg | gpg --dearmor -o /usr/share/keyrings/amnezia-ppa.gpg 2>/dev/null; echo "deb [signed-by=/usr/share/keyrings/amnezia-ppa.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu jammy main" > /etc/apt/sources.list.d/amnezia-ppa.list'`
		_, err = runInstallStep(log, srv, "Add repository (Debian)",
			debCmd, 2*time.Minute)
	}
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("добавление репозитория: %w", err)
	}

	// Step 4: apt-get update
	progressFn("Шаг 4/13: Обновление списка пакетов...")
	_, err = runInstallStep(log, srv, "apt-get update",
		"apt-get update", 3*time.Minute)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("apt-get update: %w", err)
	}

	// Step 5: Install AWG
	progressFn("Шаг 5/13: Установка AWG пакетов...")
	_, err = runInstallStep(log, srv, "Install AWG packages",
		"DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg amneziawg-tools", 5*time.Minute)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("установка AWG: %w", err)
	}

	totalSteps := 13
	if enableIPv6 && needsNdppd(ipv6IfaceAddr, ipv6ClientSubnet) {
		totalSteps = 14
	}

	// Step 6: Enable IP forwarding
	progressFn(fmt.Sprintf("Шаг 6/%d: Включение IP forwarding...", totalSteps))
	fwdCmd := `bash -c 'sysctl -w net.ipv4.ip_forward=1 && echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-awg.conf'`
	if enableIPv6 {
		// Also set accept_ra=2 on the main interface so it keeps accepting RA with forwarding=1
		fwdCmd = fmt.Sprintf(`bash -c 'sysctl -w net.ipv4.ip_forward=1 && sysctl -w net.ipv6.conf.all.forwarding=1 && sysctl -w net.ipv6.conf.%s.accept_ra=2 && printf "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nnet.ipv6.conf.%s.accept_ra=2\n" > /etc/sysctl.d/99-awg.conf'`, diag.NetIface, diag.NetIface)
	}
	_, err = runInstallStep(log, srv, "Enable IP forwarding", fwdCmd, 10*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("включение IP forwarding: %w", err)
	}

	// Step 7: Create config directory
	progressFn(fmt.Sprintf("Шаг 7/%d: Создание директории конфигов...", totalSteps))
	_, err = runInstallStep(log, srv, "Create config directory",
		fmt.Sprintf("mkdir -p %s", defaultNativeDir), 10*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("создание директории: %w", err)
	}

	// Step 8: Generate server keys
	progressFn(fmt.Sprintf("Шаг 8/%d: Генерация серверных ключей...", totalSteps))
	keyCmd := `bash -c 'priv=$(awg genkey); pub=$(echo "$priv" | awg pubkey); echo "$priv"; echo "$pub"'`
	keyOut, err := runInstallStep(log, srv, "Generate server keys", keyCmd, 10*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("генерация ключей: %w", err)
	}
	keyLines := strings.Split(strings.TrimSpace(keyOut), "\n")
	if len(keyLines) < 2 {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("неожиданный вывод генерации ключей: %s", keyOut)
	}
	serverPrivKey := strings.TrimSpace(keyLines[0])

	// Step 9: Generate AWG params (local, no SSH)
	progressFn(fmt.Sprintf("Шаг 9/%d: Генерация AWG параметров...", totalSteps))
	awgParams := generateAWGParams()
	log.AddStep("Generate AWG params", "(local)", fmt.Sprintf("%v", awgParams), true, nil, 0)

	// Step 10: Write awg0.conf
	progressFn(fmt.Sprintf("Шаг 10/%d: Запись конфигурации...", totalSteps))
	cfgIfaceAddr := ""
	cfgClientSubnet := ""
	if enableIPv6 {
		cfgIfaceAddr = ipv6IfaceAddr
		cfgClientSubnet = ipv6ClientSubnet
	}
	// generateAWGParams выдаёт набор AWG 2.0; HeaderProtectionKey и прочие
	// параметры 3.0 бот сам не генерирует (см. CLAUDE.md).
	confContent := buildServerConf(serverPrivKey, port, diag.NetIface, awgParams, cfgIfaceAddr, cfgClientSubnet, AWGVersion2)
	confB64 := base64.StdEncoding.EncodeToString([]byte(confContent))
	confWriteCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > %s/%s.conf'", confB64, defaultNativeDir, defaultIfaceName)
	_, err = runInstallStep(log, srv, "Write awg0.conf", confWriteCmd, 10*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("запись конфига: %w", err)
	}

	// Step 11: Create clientsTable
	progressFn(fmt.Sprintf("Шаг 11/%d: Создание clientsTable...", totalSteps))
	tableB64 := base64.StdEncoding.EncodeToString([]byte("[]"))
	tableCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > %s/clientsTable'", tableB64, defaultNativeDir)
	_, err = runInstallStep(log, srv, "Create clientsTable", tableCmd, 10*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("создание clientsTable: %w", err)
	}

	// Step 12 (conditional): Install and configure ndppd for NDP proxy
	if enableIPv6 && needsNdppd(cfgIfaceAddr, cfgClientSubnet) {
		progressFn(fmt.Sprintf("Шаг 12/%d: Установка ndppd (NDP proxy)...", totalSteps))
		_, err = runInstallStep(log, srv, "Install ndppd",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y ndppd", 2*time.Minute)
		if err != nil {
			// ndppd failure is non-fatal — warn but continue
			log.AddStep("Install ndppd", "(warning)", "ndppd not installed, NDP proxy may not work", true, nil, 0)
		} else {
			// Write ndppd.conf
			ndppdConf := fmt.Sprintf("proxy %s {\n  rule %s {\n    static\n  }\n}\n", diag.NetIface, cfgClientSubnet)
			ndppdB64 := base64.StdEncoding.EncodeToString([]byte(ndppdConf))
			ndppdCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > /etc/ndppd.conf'", ndppdB64)
			_, _ = runInstallStep(log, srv, "Write ndppd.conf", ndppdCmd, 10*time.Second)

			// Enable and start ndppd, configure systemd ordering
			ndppdSetup := "systemctl enable ndppd 2>/dev/null; " +
				fmt.Sprintf("mkdir -p /etc/systemd/system/ndppd.service.d && printf '[Unit]\\nAfter=awg-quick@%s.service\\nWants=awg-quick@%s.service\\n' > /etc/systemd/system/ndppd.service.d/after-awg.conf && systemctl daemon-reload", defaultIfaceName, defaultIfaceName)
			_, _ = runInstallStep(log, srv, "Configure ndppd systemd", ndppdSetup, 15*time.Second)
		}
	}

	// Step 12/13: Start service
	startStep := totalSteps - 1
	progressFn(fmt.Sprintf("Шаг %d/%d: Запуск сервиса...", startStep, totalSteps))
	_, err = runInstallStep(log, srv, "Start AWG service",
		fmt.Sprintf("systemctl enable --now awg-quick@%s", defaultIfaceName), 30*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("запуск сервиса: %w", err)
	}

	// Start ndppd after AWG is up
	if enableIPv6 && needsNdppd(cfgIfaceAddr, cfgClientSubnet) {
		_, _ = runInstallStep(log, srv, "Start ndppd", "systemctl restart ndppd 2>/dev/null", 10*time.Second)
	}

	// Last step: Verify
	progressFn(fmt.Sprintf("Шаг %d/%d: Верификация...", totalSteps, totalSteps))
	_, err = runInstallStep(log, srv, "Verify AWG",
		fmt.Sprintf("awg show %s", defaultIfaceName), 10*time.Second)
	if err != nil {
		log.FinalStatus = "failed"
		log.FinishedAt = time.Now()
		return log, diag, fmt.Errorf("верификация AWG: %w", err)
	}

	log.FinalStatus = "success"
	log.FinishedAt = time.Now()
	return log, diag, nil
}

// RollbackAWGInstall attempts to undo a failed installation.
func RollbackAWGInstall(srv ServerConfig, log *InstallLog) {
	// Map step names to rollback commands
	type rollbackAction struct {
		stepName string
		command  string
	}

	actions := []rollbackAction{
		{"Start AWG service", fmt.Sprintf("systemctl disable --now awg-quick@%s 2>/dev/null", defaultIfaceName)},
		{"Create config directory", fmt.Sprintf("rm -rf %s", defaultNativeDir)},
		{"Enable IP forwarding", "rm -f /etc/sysctl.d/99-awg.conf; sysctl --system 2>/dev/null"},
		{"Install AWG packages", "DEBIAN_FRONTEND=noninteractive apt-get remove -y amneziawg amneziawg-tools 2>/dev/null"},
		{"Add PPA", "add-apt-repository --remove -y ppa:amnezia/ppa 2>/dev/null; rm -f /etc/apt/sources.list.d/amnezia-ppa.list 2>/dev/null; rm -f /usr/share/keyrings/amnezia-ppa.gpg 2>/dev/null"},
	}

	// Find which steps succeeded
	succeeded := make(map[string]bool)
	for _, step := range log.Steps {
		if step.Success && !step.Rollback {
			succeeded[step.StepName] = true
		}
	}

	for _, action := range actions {
		if !succeeded[action.stepName] {
			continue
		}
		start := time.Now()
		output, err := SSHRunTimeout(srv, action.command, 60*time.Second)
		dur := time.Since(start)
		log.AddRollbackStep("Undo: "+action.stepName, action.command, output, err == nil, err, dur)
	}

	log.FinalStatus = "rolled_back"
	log.FinishedAt = time.Now()
}

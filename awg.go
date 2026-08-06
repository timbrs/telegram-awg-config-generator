package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	containerName     = "amnezia-awg2"
	ifaceName         = "awg0"
	defaultDockerDir  = "/opt/amnezia/awg"
	defaultNativeDir  = "/etc/amnezia/amneziawg"
)

// confDir returns the AWG config directory for the server.
func confDir(srv ServerConfig) string {
	if srv.AWGConfDir != "" {
		return srv.AWGConfDir
	}
	if srv.Mode == "native" {
		return defaultNativeDir
	}
	return defaultDockerDir
}

// confPath returns the full path to awg0.conf.
func confPath(srv ServerConfig) string {
	return confDir(srv) + "/" + ifaceName + ".conf"
}

// clientsTablePath returns the full path to clientsTable.
func clientsTablePath(srv ServerConfig) string {
	return confDir(srv) + "/clientsTable"
}

// execAWG executes an AWG command on the server (via docker exec or directly).
func execAWG(srv ServerConfig, cmd string) (string, error) {
	if srv.Mode == "native" {
		return SSHRun(srv, cmd)
	}
	return SSHRun(srv, fmt.Sprintf("docker exec %s %s", containerName, cmd))
}

// readFileOnServer reads a file on the server (via docker or directly).
func readFileOnServer(srv ServerConfig, path string) (string, error) {
	if srv.Mode == "native" {
		return SSHRun(srv, fmt.Sprintf("cat %s", path))
	}
	return SSHRun(srv, fmt.Sprintf("docker exec %s cat %s", containerName, path))
}

// writeFileOnServer writes data to a file on the server via base64.
func writeFileOnServer(srv ServerConfig, path string, data []byte) error {
	encoded := base64Encode(data)
	if srv.Mode == "native" {
		cmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > %s'", encoded, path)
		_, err := SSHRun(srv, cmd)
		return err
	}
	cmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > %s'", encoded, path)
	_, err := SSHRun(srv, fmt.Sprintf("docker exec %s %s", containerName, cmd))
	return err
}

// appendFileOnServer appends data to a file on the server via base64.
func appendFileOnServer(srv ServerConfig, path string, data []byte) error {
	encoded := base64Encode(data)
	if srv.Mode == "native" {
		cmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d >> %s'", encoded, path)
		_, err := SSHRun(srv, cmd)
		return err
	}
	cmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d >> %s'", encoded, path)
	_, err := SSHRun(srv, fmt.Sprintf("docker exec %s %s", containerName, cmd))
	return err
}

type ClientData struct {
	AllowedIPs      string `json:"allowedIps"`
	ClientName      string `json:"clientName"`
	CreationDate    string `json:"creationDate"`
	DataReceived    string `json:"dataReceived"`
	DataSent        string `json:"dataSent"`
	LatestHandshake string `json:"latestHandshake"`
	// CreatorUID — Telegram UID админа, создавшего ключ через бота. 0 означает
	// «владелец неизвестен» (ключ создан до этой фичи или через приложение Amnezia) —
	// такие ключи видны всем админам. Поле своё, Amnezia его игнорирует.
	CreatorUID int64 `json:"creatorUid,omitempty"`
}

type ClientEntry struct {
	ClientID string     `json:"clientId"`
	UserData ClientData `json:"userData"`
	ID       int        `json:"-"` // sequential 1-based ID
}

type ServerParams struct {
	PrivateKey string
	PublicKey  string
	Address    string
	ListenPort string
	DNS        string
	// AWG obfuscation params — stored as map for flexibility
	AWGParams map[string]string
	// PeerAllowedIPs — AllowedIPs из всех [Peer]-секций awg0.conf. Нужен, чтобы
	// видеть реально занятые адреса (в т.ч. клиентов, созданных самим Amnezia,
	// которых может не быть в clientsTable).
	PeerAllowedIPs []string
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// derivePublicKey вычисляет публичный WireGuard/AWG-ключ из приватного локально
// (Curve25519), без вызова `awg pubkey` на сервере. Это надёжнее: `echo $priv | awg pubkey`
// через `docker exec` периодически возвращает пустую строку из-за гонки в пайпе,
// из-за чего в конфиг попадал пустой PublicKey.
func derivePublicKey(privKeyB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privKeyB64))
	if err != nil {
		return "", fmt.Errorf("декодирование приватного ключа: %w", err)
	}
	if len(priv) != 32 {
		return "", fmt.Errorf("приватный ключ должен быть 32 байта, получено %d", len(priv))
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("вычисление публичного ключа: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// writeClientsTable marshals the clients list and writes it to the server.
func writeClientsTable(srv ServerConfig, clients []ClientEntry) error {
	if clients == nil {
		clients = []ClientEntry{}
	}
	tableJSON, err := json.Marshal(clients)
	if err != nil {
		return fmt.Errorf("сериализация clientsTable: %w", err)
	}

	if err := writeFileOnServer(srv, clientsTablePath(srv), tableJSON); err != nil {
		return fmt.Errorf("обновление clientsTable: %w", err)
	}
	return nil
}

func GetAmneziaDNSIP(srv ServerConfig) string {
	if srv.Mode == "native" {
		return "" // no Docker DNS container in native mode
	}
	out, err := SSHRun(srv, `docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' amnezia-dns`)
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(out)
	if ip == "" || strings.Contains(ip, "Error") {
		return ""
	}
	return ip
}

func ListClients(srv ServerConfig) ([]ClientEntry, error) {
	output, err := readFileOnServer(srv, clientsTablePath(srv))
	if err != nil {
		return nil, fmt.Errorf("чтение clientsTable: %w", err)
	}

	output = strings.TrimSpace(output)
	if output == "" || output == "[]" {
		return nil, nil
	}

	var entries []ClientEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return nil, fmt.Errorf("парсинг clientsTable на %s: %w\nСодержимое: %s", srv.Name, err, output)
	}

	for i := range entries {
		entries[i].ID = i + 1
	}

	return entries, nil
}

func ReadServerConfig(srv ServerConfig) (*ServerParams, error) {
	output, err := readFileOnServer(srv, confPath(srv))
	if err != nil {
		return nil, fmt.Errorf("чтение awg конфига: %w", err)
	}

	params := &ServerParams{AWGParams: make(map[string]string)}
	// Known AWG obfuscation parameter names
	awgKeys := map[string]bool{
		"Jc": true, "Jmin": true, "Jmax": true,
		"S1": true, "S2": true, "S3": true, "S4": true,
		"H1": true, "H2": true, "H3": true, "H4": true,
		"I1": true, "I2": true, "I3": true, "I4": true, "I5": true,
	}

	lines := strings.Split(output, "\n")
	section := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[Interface]" {
			section = "interface"
			continue
		}
		if line == "[Peer]" {
			section = "peer"
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			case "PrivateKey":
				params.PrivateKey = val
			case "Address":
				params.Address = val
			case "ListenPort":
				params.ListenPort = val
			case "DNS":
				params.DNS = val
			default:
				if awgKeys[key] {
					params.AWGParams[key] = val
				}
			}
		case "peer":
			if key == "AllowedIPs" {
				params.PeerAllowedIPs = append(params.PeerAllowedIPs, val)
			}
		}
	}

	// Derive public key from private key locally (Curve25519).
	pub, err := derivePublicKey(params.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("получение публичного ключа сервера: %w", err)
	}
	params.PublicKey = pub

	return params, nil
}

func GenerateKeyPair(srv ServerConfig) (privKey, pubKey, psk string, err error) {
	// Генерируем на сервере только приватный ключ и PSK; публичный ключ выводим
	// локально через Curve25519. Это надёжнее: `echo $priv | awg pubkey` через
	// `docker exec` периодически отдаёт пустую строку (гонка в пайпе), из-за чего
	// на сервер мог добавиться пир с пустым PublicKey.
	cmd := `sh -c 'awg genkey; awg genpsk'`
	output, err := execAWG(srv, cmd)
	if err != nil {
		return "", "", "", fmt.Errorf("генерация ключей: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		return "", "", "", fmt.Errorf("неожиданный вывод генерации ключей: %s", output)
	}
	privKey = strings.TrimSpace(lines[0])
	psk = strings.TrimSpace(lines[len(lines)-1])

	pubKey, err = derivePublicKey(privKey)
	if err != nil {
		return "", "", "", fmt.Errorf("деривация публичного ключа клиента: %w", err)
	}

	return privKey, pubKey, psk, nil
}

// allocateIP выделяет свободный IPv4-адрес для нового клиента.
//
// Адрес выделяется в РЕАЛЬНОЙ подсети сервера, прочитанной из awg0.conf
// (srvParams.Address, например "10.8.1.0/24"). Это критично: маршрут, NAT и
// forwarding на сервере настроены ровно на эту подсеть, поэтому клиент с адресом
// из другой подсети (раньше бот хардкодил 10.8.0.0/22) получает рукопожатие, но
// обратный трафик к нему не маршрутизируется.
//
// Занятые адреса берутся из реальных [Peer]-секций (srvParams.PeerAllowedIPs) и
// из clientsTable, плюс сам адрес сервера. Если подсеть определить не удалось,
// используется прежнее поведение (10.8.0.0/22) как запасной вариант.
func allocateIP(srvParams *ServerParams, clients []ClientEntry) (string, error) {
	used := make(map[string]bool)
	markUsed := func(s string) {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ipStr := strings.Split(part, "/")[0]
			if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
				used[ip.String()] = true
			}
		}
	}
	if srvParams != nil {
		for _, p := range srvParams.PeerAllowedIPs {
			markUsed(p)
		}
	}
	for _, c := range clients {
		markUsed(c.UserData.AllowedIPs) // dual-stack: "10.8.0.5/32, fd00:awg::5/128"
	}

	// Выделение в реальной подсети сервера.
	if srvParams != nil && srvParams.Address != "" {
		serverIP, ipnet, err := net.ParseCIDR(srvParams.Address)
		if err == nil && serverIP.To4() != nil {
			used[serverIP.To4().String()] = true // адрес сервера не выдаём
			if ip, ok := firstFreeIPv4(ipnet, used); ok {
				return ip, nil
			}
			return "", fmt.Errorf("нет свободных IP-адресов в подсети %s", srvParams.Address)
		}
	}

	// Запасной вариант: историческая подсеть 10.8.0.2 — 10.8.3.254 (/22).
	for o3 := 0; o3 <= 3; o3++ {
		start := 2
		if o3 > 0 {
			start = 1
		}
		for o4 := start; o4 <= 254; o4++ {
			ip := fmt.Sprintf("10.8.%d.%d", o3, o4)
			if !used[ip] {
				return ip, nil
			}
		}
	}
	return "", fmt.Errorf("нет свободных IP-адресов (лимит 1021)")
}

// firstFreeIPv4 возвращает первый свободный адрес-хост в IPv4-подсети, пропуская
// сетевой адрес, broadcast и адреса из used.
func firstFreeIPv4(ipnet *net.IPNet, used map[string]bool) (string, bool) {
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return "", false
	}
	base := binary.BigEndian.Uint32(ipnet.IP.Mask(ipnet.Mask).To4())
	size := uint32(1) << uint(bits-ones)
	// off в диапазоне 1..size-2 — исключаем сетевой адрес (0) и broadcast (size-1).
	for off := uint32(1); off+1 < size; off++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+off)
		ip := net.IPv4(b[0], b[1], b[2], b[3]).To4().String()
		if !used[ip] {
			return ip, true
		}
	}
	return "", false
}

// IPv6AllocResult holds the result of an IPv6 allocation.
type IPv6AllocResult struct {
	// ClientAddr is the client's own IPv6 address (e.g. "2a01:db8::1:1").
	ClientAddr string
	// AllowedMask is the prefix length for AllowedIPs on the server side.
	// /112 when allocating subnets, /128 when allocating single addresses.
	AllowedMask int
	// SubnetBase is the base address of the allocated subnet (for /112 mode).
	// Empty for single-address allocations.
	SubnetBase string
}

// allocateIPv6 allocates the next free IPv6 address or subnet from a pool.
//
// Modes based on CIDR prefix length:
//   - /96: allocate /112 subnets (each client gets prefix::N:0/112, addr prefix::N:1)
//   - /112 or larger: allocate individual addresses within the CIDR
//   - bare prefix (no /): legacy string-based allocation
func allocateIPv6(clients []ClientEntry, subnetCIDR string) (*IPv6AllocResult, error) {
	// Build set of used IPv6 addresses/subnets (canonical form)
	usedCanonical := make(map[string]bool)
	usedRaw := make(map[string]bool)
	for _, c := range clients {
		for _, part := range strings.Split(c.UserData.AllowedIPs, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, ":") {
				raw := strings.Split(part, "/")[0]
				usedRaw[strings.ToLower(raw)] = true
				if ip := net.ParseIP(raw); ip != nil {
					usedCanonical[ip.String()] = true
				}
			}
		}
	}

	// Try CIDR parsing
	if strings.Contains(subnetCIDR, "/") {
		_, ipNet, err := net.ParseCIDR(subnetCIDR)
		if err == nil {
			ones, _ := ipNet.Mask.Size()

			// /96 pool → allocate /112 subnets per client
			if ones <= 96 {
				return allocateIPv6Subnet112(ipNet, usedCanonical)
			}

			// /112 or tighter → allocate individual addresses
			return allocateIPv6Address(ipNet, usedCanonical, subnetCIDR)
		}
	}

	// Fallback: bare prefix like "fd00:awg::"
	return allocateIPv6Legacy(clients, subnetCIDR)
}

// allocateIPv6Subnet112 allocates /112 subnets from a /96 pool.
// Client N gets prefix::N:0/112 with address prefix::N:1.
func allocateIPv6Subnet112(pool *net.IPNet, used map[string]bool) (*IPv6AllocResult, error) {
	base := make(net.IP, 16)
	copy(base, pool.IP.To16())

	// Subnet IDs 1 to 0xFFFE (bytes 12-13 of the IPv6 address)
	for subnetID := 1; subnetID <= 0xFFFE; subnetID++ {
		// Build subnet base: prefix::subnetID:0
		subnetBase := make(net.IP, 16)
		copy(subnetBase, base)
		subnetBase[12] = byte(subnetID >> 8)
		subnetBase[13] = byte(subnetID & 0xFF)
		// bytes 14-15 stay 0

		// Check if any address in this /112 is already used
		if used[subnetBase.String()] {
			continue
		}
		// Also check the first usable address (::N:1)
		clientAddr := make(net.IP, 16)
		copy(clientAddr, subnetBase)
		clientAddr[15] = 1
		if used[clientAddr.String()] {
			continue
		}

		return &IPv6AllocResult{
			ClientAddr:  clientAddr.String(),
			AllowedMask: 112,
			SubnetBase:  subnetBase.String(),
		}, nil
	}
	return nil, fmt.Errorf("нет свободных /112 подсетей")
}

// allocateIPv6Address allocates individual addresses within a CIDR (e.g. /112, /114).
func allocateIPv6Address(ipNet *net.IPNet, used map[string]bool, cidr string) (*IPv6AllocResult, error) {
	base := make(net.IP, 16)
	copy(base, ipNet.IP.To16())
	ones, bits := ipNet.Mask.Size()
	hostBits := uint(bits - ones)
	maxHost := (1 << hostBits) - 2
	if maxHost > 0xFFFE {
		maxHost = 0xFFFE
	}

	for i := 1; i <= maxHost; i++ {
		candidate := make(net.IP, 16)
		copy(candidate, base)
		addHostToIPv6(candidate, i)
		if !used[candidate.String()] {
			return &IPv6AllocResult{
				ClientAddr:  candidate.String(),
				AllowedMask: 128,
			}, nil
		}
	}
	return nil, fmt.Errorf("нет свободных IPv6-адресов в %s", cidr)
}

// allocateIPv6Legacy handles bare prefix strings like "fd00:awg::".
func allocateIPv6Legacy(clients []ClientEntry, subnetCIDR string) (*IPv6AllocResult, error) {
	vpnPrefix := strings.TrimSuffix(subnetCIDR, "::")
	if !strings.HasSuffix(vpnPrefix, ":") {
		vpnPrefix += "::"
	} else {
		vpnPrefix += ":"
	}

	usedRaw := make(map[string]bool)
	for _, c := range clients {
		for _, part := range strings.Split(c.UserData.AllowedIPs, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, ":") {
				raw := strings.Split(part, "/")[0]
				usedRaw[strings.ToLower(raw)] = true
			}
		}
	}

	for i := 2; i <= 0xFFFE; i++ {
		ip := fmt.Sprintf("%s%x", vpnPrefix, i)
		if !usedRaw[strings.ToLower(ip)] {
			return &IPv6AllocResult{
				ClientAddr:  ip,
				AllowedMask: 128,
			}, nil
		}
	}
	return nil, fmt.Errorf("нет свободных IPv6-адресов")
}

// addHostToIPv6 adds a host ID number to an IPv6 address (big-endian addition).
func addHostToIPv6(ip net.IP, hostID int) {
	for i := 15; i >= 0 && hostID > 0; i-- {
		sum := int(ip[i]) + hostID%256
		ip[i] = byte(sum % 256)
		hostID = hostID/256 + sum/256
	}
}

func AddPeer(srv ServerConfig, name string, creatorUID int64) (clientConf string, vpnURI string, err error) {
	privKey, pubKey, psk, err := GenerateKeyPair(srv)
	if err != nil {
		return "", "", err
	}

	clients, err := ListClients(srv)
	if err != nil {
		return "", "", err
	}

	srvParams, err := ReadServerConfig(srv)
	if err != nil {
		return "", "", err
	}

	newIP, err := allocateIP(srvParams, clients)
	if err != nil {
		return "", "", err
	}

	dns1, dns2 := "8.8.8.8", "8.8.4.4"
	if dnsIP := GetAmneziaDNSIP(srv); dnsIP != "" {
		dns1 = dnsIP
	}

	// IPv6 allocation
	clientIPv6 := ""
	clientIPv6Mask := "128"
	allowedIPs := newIP + "/32"
	if srv.IPv6Subnet != "" {
		alloc, ipv6Err := allocateIPv6(clients, srv.IPv6Subnet)
		if ipv6Err != nil {
			log.Printf("IPv6 allocation failed: %v", ipv6Err)
		} else {
			clientIPv6 = alloc.ClientAddr
			clientIPv6Mask = strconv.Itoa(alloc.AllowedMask)
			if alloc.AllowedMask == 112 && alloc.SubnetBase != "" {
				// Subnet allocation: AllowedIPs uses the /112 subnet base
				allowedIPs = fmt.Sprintf("%s/32, %s/%d", newIP, alloc.SubnetBase, alloc.AllowedMask)
			} else {
				allowedIPs = fmt.Sprintf("%s/32, %s/%d", newIP, clientIPv6, alloc.AllowedMask)
			}
		}
	}

	// Append [Peer] block to config via base64 to avoid shell escaping issues
	peerBlock := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", pubKey, psk, allowedIPs)

	if err := appendFileOnServer(srv, confPath(srv), []byte(peerBlock)); err != nil {
		return "", "", fmt.Errorf("добавление пира в конфиг: %w", err)
	}

	// Update clientsTable
	newEntry := ClientEntry{
		ClientID: pubKey,
		UserData: ClientData{
			AllowedIPs:      allowedIPs,
			ClientName:      name,
			CreationDate:    "just now",
			DataReceived:    "0 B",
			DataSent:        "0 B",
			LatestHandshake: "never",
			CreatorUID:      creatorUID,
		},
	}
	clients = append(clients, newEntry)

	if err := writeClientsTable(srv, clients); err != nil {
		return "", "", err
	}

	// Reload interface (bash needed for process substitution)
	reloadCmd := fmt.Sprintf("bash -c 'awg syncconf %s <(awg-quick strip %s)'", ifaceName, confPath(srv))
	if _, err := execAWG(srv, reloadCmd); err != nil {
		return "", "", fmt.Errorf("перезагрузка интерфейса: %w", err)
	}

	// Build client config (AmneziaWG format).
	// Endpoint берётся из EndpointHost() — публичный IPv4, даже если SSH идёт по IPv6.
	endpointHost := srv.EndpointHost()
	clientConf = BuildClientConfig(privKey, psk, newIP, endpointHost, srvParams.ListenPort, dns1, dns2, srvParams, clientIPv6, clientIPv6Mask)

	// Build AmneziaVPN URI (non-fatal on error)
	vpnURI, _, vpnErr := BuildAmneziaVPNURI(privKey, pubKey, psk, newIP, endpointHost, srvParams.ListenPort, srv.Name, dns1, dns2, srvParams)
	if vpnErr != nil {
		log.Printf("AmneziaVPN URI build failed: %v", vpnErr)
	}

	return clientConf, vpnURI, nil
}

func removePeerBlock(confText, pubKey string) string {
	lines := strings.Split(confText, "\n")
	var result []string

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		if trimmed == "[Peer]" {
			// Заглядываем вперёд до следующего [Peer]/[Interface] — это весь блок
			// текущего пира. Если в нём наш pubKey — пропускаем блок целиком.
			j := i + 1
			found := false
			for j < len(lines) {
				t := strings.TrimSpace(lines[j])
				if t == "[Peer]" || t == "[Interface]" {
					break
				}
				if strings.HasPrefix(t, "PublicKey") && strings.Contains(t, pubKey) {
					found = true
				}
				j++
			}
			if found {
				// Пропустить строки [i..j-1]; следующая итерация начнётся с lines[j].
				i = j - 1
				continue
			}
		}

		result = append(result, lines[i])
	}

	// Clean up trailing blank lines
	text := strings.Join(result, "\n")
	for strings.HasSuffix(text, "\n\n\n") {
		text = strings.TrimSuffix(text, "\n")
	}
	return text
}

func RemovePeer(srv ServerConfig, pubKey string) error {
	// Remove from awg interface
	removeCmd := fmt.Sprintf("awg set %s peer %s remove", ifaceName, pubKey)
	if _, err := execAWG(srv, removeCmd); err != nil {
		return fmt.Errorf("удаление пира из интерфейса: %w", err)
	}

	// Read config, remove peer block in Go, write back
	confText, err := readFileOnServer(srv, confPath(srv))
	if err != nil {
		return fmt.Errorf("чтение awg конфига для удаления: %w", err)
	}

	newConf := removePeerBlock(confText, pubKey)

	if err := writeFileOnServer(srv, confPath(srv), []byte(newConf)); err != nil {
		return fmt.Errorf("запись обновлённого конфига: %w", err)
	}

	// Update clientsTable - remove the entry
	clients, err := ListClients(srv)
	if err != nil {
		return fmt.Errorf("чтение clientsTable для удаления: %w", err)
	}

	var updated []ClientEntry
	for _, c := range clients {
		if c.ClientID != pubKey {
			updated = append(updated, c)
		}
	}

	if err := writeClientsTable(srv, updated); err != nil {
		return err
	}

	return nil
}

// PeerStats holds live stats from "awg show"
type PeerStats struct {
	LatestHandshake string
	TransferRx      string
	TransferTx      string
}

// AWGShow runs "awg show <iface>" and parses per-peer stats keyed by public key.
func AWGShow(srv ServerConfig) (map[string]PeerStats, error) {
	output, err := execAWG(srv, fmt.Sprintf("awg show %s", ifaceName))
	if err != nil {
		return nil, fmt.Errorf("awg show: %w", err)
	}

	peers := make(map[string]PeerStats)
	var curPeer string
	var cur PeerStats

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if curPeer != "" {
				peers[curPeer] = cur
				curPeer = ""
				cur = PeerStats{}
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "peer":
			if curPeer != "" {
				peers[curPeer] = cur
			}
			curPeer = val
			cur = PeerStats{}
		case "latest handshake":
			cur.LatestHandshake = val
		case "transfer":
			// format: "X.XX MiB received, Y.YY MiB sent"
			tp := strings.SplitN(val, ",", 2)
			if len(tp) == 2 {
				cur.TransferRx = strings.TrimSuffix(strings.TrimSpace(tp[0]), " received")
				cur.TransferTx = strings.TrimSuffix(strings.TrimSpace(tp[1]), " sent")
			}
		}
	}
	if curPeer != "" {
		peers[curPeer] = cur
	}

	return peers, nil
}

// PeerTraffic holds raw byte counts from "awg show <iface> dump".
type PeerTraffic struct {
	PubKey string
	Rx     int64
	Tx     int64
}

// AWGShowDump runs "awg show <iface> dump" and returns raw byte counts per peer.
func AWGShowDump(srv ServerConfig) ([]PeerTraffic, error) {
	output, err := execAWG(srv, fmt.Sprintf("awg show %s dump", ifaceName))
	if err != nil {
		return nil, fmt.Errorf("awg show dump: %w", err)
	}

	var peers []PeerTraffic
	for i, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if i == 0 {
			continue // skip interface line
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		// fields: public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
		rx, err1 := strconv.ParseInt(fields[5], 10, 64)
		tx, err2 := strconv.ParseInt(fields[6], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		peers = append(peers, PeerTraffic{
			PubKey: fields[0],
			Rx:     rx,
			Tx:     tx,
		})
	}
	return peers, nil
}

func RenamePeer(srv ServerConfig, pubKey, newName string) error {
	clients, err := ListClients(srv)
	if err != nil {
		return err
	}

	found := false
	for i, c := range clients {
		if c.ClientID == pubKey {
			clients[i].UserData.ClientName = newName
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("клиент не найден")
	}

	return writeClientsTable(srv, clients)
}

// BuildClientConfig generates a WireGuard .conf for a client.
// clientIPv6 is optional: [0]=address, [1]=prefix length (default "128").
func BuildClientConfig(privKey, psk, clientIP, serverIP, serverPort, dns1, dns2 string, params *ServerParams, clientIPv6 ...string) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))

	addr := clientIP + "/32"
	if len(clientIPv6) > 0 && clientIPv6[0] != "" {
		v6mask := "128"
		if len(clientIPv6) > 1 && clientIPv6[1] != "" {
			v6mask = clientIPv6[1]
		}
		addr += ", " + clientIPv6[0] + "/" + v6mask
	}
	sb.WriteString(fmt.Sprintf("Address = %s\n", addr))

	dnsLine := fmt.Sprintf("%s, %s", dns1, dns2)
	if len(clientIPv6) > 0 && clientIPv6[0] != "" {
		dnsLine += ", 2001:4860:4860::8888"
	}
	sb.WriteString(fmt.Sprintf("DNS = %s\n", dnsLine))

	// Write AWG params in deterministic order
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"} {
		if val, ok := params.AWGParams[key]; ok {
			sb.WriteString(fmt.Sprintf("%s = %s\n", key, val))
		}
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", params.PublicKey))
	sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
	sb.WriteString(fmt.Sprintf("Endpoint = %s:%s\n", serverIP, serverPort))
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}

// AmneziaVPN JSON config types
type amneziaVPNConfig struct {
	Containers           []amneziaContainer `json:"containers"`
	DefaultContainer     string             `json:"defaultContainer"`
	Description          string             `json:"description"`
	DNS1                 string             `json:"dns1"`
	DNS2                 string             `json:"dns2"`
	HostName             string             `json:"hostName"`
	NameOverriddenByUser bool               `json:"nameOverriddenByUser"`
}

type amneziaContainer struct {
	Container string         `json:"container"`
	AWG       amneziaAWGData `json:"awg"`
}

type amneziaAWGData struct {
	Jc              string `json:"Jc,omitempty"`
	Jmin            string `json:"Jmin,omitempty"`
	Jmax            string `json:"Jmax,omitempty"`
	S1              string `json:"S1,omitempty"`
	S2              string `json:"S2,omitempty"`
	S3              string `json:"S3,omitempty"`
	S4              string `json:"S4,omitempty"`
	H1              string `json:"H1,omitempty"`
	H2              string `json:"H2,omitempty"`
	H3              string `json:"H3,omitempty"`
	H4              string `json:"H4,omitempty"`
	I1              string `json:"I1"`
	I2              string `json:"I2"`
	I3              string `json:"I3"`
	I4              string `json:"I4"`
	I5              string `json:"I5"`
	LastConfig      string `json:"last_config"`
	Port            string `json:"port"`
	ProtocolVersion string `json:"protocol_version"`
	SubnetAddress   string `json:"subnet_address,omitempty"`
	TransportProto  string `json:"transport_proto"`
}

// BuildAmneziaVPNURI builds a vpn:// URI for AmneziaVPN app.
func BuildAmneziaVPNURI(privKey, pubKey, psk, clientIP, serverIP, serverPort, serverName, dns1, dns2 string, params *ServerParams) (vpnURI string, compressedData []byte, err error) {
	// Determine container type: awg2 if S3/S4 present, otherwise awg
	containerType := "amnezia-awg"
	protoVersion := "1"
	if _, hasS3 := params.AWGParams["S3"]; hasS3 {
		containerType = "amnezia-awg2"
		protoVersion = "2"
		// Ensure I1-I5 exist for v2 (empty string if not set by server)
		for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if _, ok := params.AWGParams[k]; !ok {
				params.AWGParams[k] = ""
			}
		}
	}

	// Build the full WG+AWG config text
	confText := BuildClientConfig(privKey, psk, clientIP, serverIP, serverPort, dns1, dns2, params)

	// Parse port as integer for last_config (AmneziaVPN expects number)
	portNum, _ := strconv.Atoi(serverPort)

	// last_config is a stringified JSON matching AmneziaVPN's internal format
	lastConfigMap := map[string]interface{}{
		"config":                confText,
		"client_priv_key":       privKey,
		"client_pub_key":        pubKey,
		"clientId":              pubKey,
		"server_pub_key":        params.PublicKey,
		"psk_key":               psk,
		"client_ip":             clientIP,
		"hostName":              serverIP,
		"port":                  portNum,
		"mtu":                   "1376",
		"persistent_keep_alive": "25",
		"allowed_ips":           []string{"0.0.0.0/0", "::/0"},
	}
	// Copy ALL AWG params into last_config (including I1-I5 for v2)
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"} {
		if v, ok := params.AWGParams[key]; ok {
			lastConfigMap[key] = v
		}
	}
	lastConfigBytes, err2 := json.MarshalIndent(lastConfigMap, "", "    ")
	if err2 != nil {
		return "", nil, fmt.Errorf("marshal last_config: %w", err2)
	}

	// Derive subnet from client IP (e.g. 10.8.1.48 → 10.8.1.0)
	subnetAddr := ""
	if parts := strings.Split(clientIP, "."); len(parts) == 4 {
		subnetAddr = parts[0] + "." + parts[1] + "." + parts[2] + ".0"
	}

	awgData := amneziaAWGData{
		LastConfig:      string(lastConfigBytes),
		Port:            serverPort,
		ProtocolVersion: protoVersion,
		SubnetAddress:   subnetAddr,
		TransportProto:  "udp",
	}
	// Duplicate AWG params at container level
	if v, ok := params.AWGParams["Jc"]; ok {
		awgData.Jc = v
	}
	if v, ok := params.AWGParams["Jmin"]; ok {
		awgData.Jmin = v
	}
	if v, ok := params.AWGParams["Jmax"]; ok {
		awgData.Jmax = v
	}
	if v, ok := params.AWGParams["S1"]; ok {
		awgData.S1 = v
	}
	if v, ok := params.AWGParams["S2"]; ok {
		awgData.S2 = v
	}
	if v, ok := params.AWGParams["S3"]; ok {
		awgData.S3 = v
	}
	if v, ok := params.AWGParams["S4"]; ok {
		awgData.S4 = v
	}
	if v, ok := params.AWGParams["H1"]; ok {
		awgData.H1 = v
	}
	if v, ok := params.AWGParams["H2"]; ok {
		awgData.H2 = v
	}
	if v, ok := params.AWGParams["H3"]; ok {
		awgData.H3 = v
	}
	if v, ok := params.AWGParams["H4"]; ok {
		awgData.H4 = v
	}
	if v, ok := params.AWGParams["I1"]; ok {
		awgData.I1 = v
	}
	if v, ok := params.AWGParams["I2"]; ok {
		awgData.I2 = v
	}
	if v, ok := params.AWGParams["I3"]; ok {
		awgData.I3 = v
	}
	if v, ok := params.AWGParams["I4"]; ok {
		awgData.I4 = v
	}
	if v, ok := params.AWGParams["I5"]; ok {
		awgData.I5 = v
	}

	cfg := amneziaVPNConfig{
		Containers: []amneziaContainer{
			{
				Container: containerType,
				AWG:       awgData,
			},
		},
		DefaultContainer:     containerType,
		Description:          serverName,
		DNS1:                 dns1,
		DNS2:                 dns2,
		HostName:             serverIP,
		NameOverriddenByUser: true,
	}

	jsonBytes, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return "", nil, fmt.Errorf("marshal AmneziaVPN config: %w", err)
	}

	// Compress with zlib (Qt qCompress format: 4-byte big-endian uncompressed size + zlib data)
	var zlibBuf bytes.Buffer
	w := zlib.NewWriter(&zlibBuf)
	if _, err := w.Write(jsonBytes); err != nil {
		return "", nil, fmt.Errorf("zlib compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", nil, fmt.Errorf("zlib close: %w", err)
	}

	// Prepend Qt 4-byte header (uncompressed size, big-endian)
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(jsonBytes))); err != nil {
		return "", nil, fmt.Errorf("write qt header: %w", err)
	}
	buf.Write(zlibBuf.Bytes())

	compressed := buf.Bytes()

	// Encode as base64url (no padding) for vpn:// URI
	uri := "vpn://" + base64.RawURLEncoding.EncodeToString(compressed)

	return uri, compressed, nil
}

// detectAWGMode connects via SSH and determines AWG mode (docker/native) and config directory.
func detectAWGMode(ip, login, pass string) (mode string, awgConfDir string, err error) {
	tmpSrv := ServerConfig{IP: ip, Login: login, Pass: pass}

	// Try Docker first
	dockerCmd := fmt.Sprintf("docker exec %s awg show %s", containerName, ifaceName)
	if _, err := SSHRun(tmpSrv, dockerCmd); err == nil {
		return "docker", defaultDockerDir, nil
	}

	// Try native
	if _, err := SSHRun(tmpSrv, fmt.Sprintf("awg show %s", ifaceName)); err == nil {
		// Check known config paths
		paths := []string{
			"/etc/amnezia/amneziawg",
			"/etc/wireguard",
		}
		for _, p := range paths {
			if _, testErr := SSHRun(tmpSrv, fmt.Sprintf("test -f %s/%s.conf", p, ifaceName)); testErr == nil {
				return "native", p, nil
			}
		}
		return "native", defaultNativeDir, nil
	}

	return "", "", fmt.Errorf("AWG не обнаружен на сервере %s", ip)
}

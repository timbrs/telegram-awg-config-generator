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
	containerName = "amnezia-awg2"
	// defaultIfaceName — имя интерфейса по умолчанию. Использовать напрямую можно
	// только там, где интерфейс создаётся самим ботом (установка AWG); для работы
	// с уже настроенным сервером берите srv.IfaceName().
	defaultIfaceName = "awg0"
	defaultDockerDir = "/opt/amnezia/awg"
	defaultNativeDir = "/etc/amnezia/amneziawg"
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

// confPath returns the full path to <iface>.conf.
func confPath(srv ServerConfig) string {
	return confDir(srv) + "/" + srv.IfaceName() + ".conf"
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
//
// umask 077 + chmod 600 обязательны: под дефолтным umask 022 приватный ключ
// сервера в awg0.conf становится world-readable, а `awg-quick strip` ругается
// на права, отличные от 0600.
func writeFileOnServer(srv ServerConfig, path string, data []byte) error {
	cmd := fmt.Sprintf("bash -c 'umask 077; printf %%s %s | base64 -d > %s && chmod 600 %s'",
		base64Encode(data), path, path)
	if srv.Mode == "native" {
		_, err := SSHRun(srv, cmd)
		return err
	}
	_, err := SSHRun(srv, fmt.Sprintf("docker exec %s %s", containerName, cmd))
	return err
}

// appendFileOnServer appends data to a file on the server via base64.
func appendFileOnServer(srv ServerConfig, path string, data []byte) error {
	cmd := fmt.Sprintf("bash -c 'umask 077; printf %%s %s | base64 -d >> %s'",
		base64Encode(data), path)
	if srv.Mode == "native" {
		_, err := SSHRun(srv, cmd)
		return err
	}
	_, err := SSHRun(srv, fmt.Sprintf("docker exec %s %s", containerName, cmd))
	return err
}

// fileExistsOnServer проверяет наличие файла. Команда всегда завершается
// успешно, поэтому «файла нет» надёжно отличается от «SSH не отработал»:
// SSHRun не различает ненулевой exit code и обрыв соединения.
func fileExistsOnServer(srv ServerConfig, path string) (bool, error) {
	out, err := execAWG(srv, fmt.Sprintf("sh -c 'test -f %s && echo AWGYES || echo AWGNO'", path))
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "AWGYES"), nil
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
	// ClientPort — UDP-порт в Endpoint клиента при режиме «случайный порт».
	// 0 означает штатный ListenPort сервера. Поле своё, Amnezia его игнорирует.
	ClientPort int `json:"clientPort,omitempty"`
}

type ClientEntry struct {
	ClientID string     `json:"clientId"`
	UserData ClientData `json:"userData"`
	ID       int        `json:"-"` // sequential 1-based ID
}

// PeerBlock — одна [Peer]-секция серверного конфига.
type PeerBlock struct {
	PublicKey  string
	AllowedIPs string
}

type ServerParams struct {
	PrivateKey string
	PublicKey  string
	Address    string
	ListenPort string
	DNS        string
	// AWGParams — ВСЕ obfuscation-параметры из [Interface] серверного конфига.
	// Клиентские значения не вычисляются, а копируются отсюда: так must-match
	// параметры (S1-S4, H1-H4, HeaderProtectionKey) физически не могут
	// разъехаться между сервером и клиентом, а новая версия протокола
	// подхватывается без правок кода.
	AWGParams map[string]string
	// ExtraParamOrder — ключи вне awgParamSpecs, в порядке появления в конфиге.
	// Нужен, чтобы вывод нераспознанных параметров был детерминированным.
	ExtraParamOrder []string
	// Version — версия протокола, выведенная из набора параметров конфига.
	Version AWGVersion
	// ClientMTU — MTU для клиентских конфигов, посчитанный по S4 сервера и
	// MTU его HOP-туннеля (см. mtu.go). 0 = не считали (парсинг без SSH).
	ClientMTU int
	// PeerAllowedIPs — AllowedIPs из всех [Peer]-секций awg0.conf. Нужен, чтобы
	// видеть реально занятые адреса (в т.ч. клиентов, созданных самим Amnezia,
	// которых может не быть в clientsTable).
	PeerAllowedIPs []string
	// Peers — [Peer]-секции целиком. Нужны, чтобы восстановить clientsTable на
	// сервере, настроенном вручную (без Amnezia).
	Peers []PeerBlock
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

// clientsFromPeers восстанавливает список клиентов из [Peer]-секций конфига.
func clientsFromPeers(srv ServerConfig) ([]ClientEntry, error) {
	params, err := ReadServerConfig(srv)
	if err != nil {
		return nil, fmt.Errorf("восстановление clientsTable из конфига: %w", err)
	}
	log.Printf("AWG (%s): clientsTable не найден, восстанавливаю из [Peer]-секций (%d шт.)", srv.Name, len(params.Peers))
	return buildClientsFromPeers(params.Peers), nil
}

// buildClientsFromPeers — чистая часть clientsFromPeers.
func buildClientsFromPeers(peers []PeerBlock) []ClientEntry {
	var entries []ClientEntry
	for _, p := range peers {
		if p.PublicKey == "" {
			continue
		}
		n := len(entries) + 1
		entries = append(entries, ClientEntry{
			ClientID: p.PublicKey,
			UserData: ClientData{
				AllowedIPs:      p.AllowedIPs,
				ClientName:      fmt.Sprintf("peer-%d", n),
				CreationDate:    "unknown",
				DataReceived:    "0 B",
				DataSent:        "0 B",
				LatestHandshake: "never",
				// CreatorUID = 0 — ключ «ничей», виден всем админам сервера.
			},
			ID: n,
		})
	}
	return entries
}

// resolveClientDNS выбирает DNS для клиентского конфига по убыванию приоритета:
//  1. srv.DNS из config.yaml — явный выбор админа, без SSH;
//  2. DNS = из [Interface] серверного конфига (уже в ServerParams.DNS);
//  3. контейнер amnezia-dns — только в docker-режиме;
//  4. 8.8.8.8 / 8.8.4.4.
func resolveClientDNS(srv ServerConfig, params *ServerParams) (dns1, dns2 string) {
	const fallback1, fallback2 = "8.8.8.8", "8.8.4.4"

	if d1, d2, ok := splitDNSPair(srv.DNS); ok {
		return d1, orDefault(d2, fallback2)
	}
	if params != nil {
		if d1, d2, ok := splitDNSPair(params.DNS); ok {
			return d1, orDefault(d2, fallback2)
		}
	}
	if srv.Mode != "native" {
		if ip := GetAmneziaDNSIP(srv); ip != "" {
			return ip, fallback2
		}
	}
	return fallback1, fallback2
}

// splitDNSPair разбирает "1.1.1.1, 1.0.0.1" на пару адресов.
func splitDNSPair(s string) (dns1, dns2 string, ok bool) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		switch {
		case dns1 == "":
			dns1 = part
		case dns2 == "":
			dns2 = part
		}
	}
	return dns1, dns2, dns1 != ""
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
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

// ListClients возвращает клиентов из clientsTable. Если файла нет (сервер настроен
// вручную, а не через Amnezia), таблица восстанавливается из [Peer]-секций конфига:
// имя = "peer-N", creatorUid = 0 (ключ «ничей», виден всем админам).
//
// Восстановленная таблица НЕ пишется на сервер при чтении — только при следующем
// изменении (AddPeer/RemovePeer вызывают writeClientsTable сами). Чтение без
// побочных эффектов, к тому же так настоящая таблица, временно недоступная из-за
// сетевой ошибки, не будет затёрта: «файла нет» проверяется явным test -f.
func ListClients(srv ServerConfig) ([]ClientEntry, error) {
	output, err := readFileOnServer(srv, clientsTablePath(srv))
	if err != nil {
		exists, testErr := fileExistsOnServer(srv, clientsTablePath(srv))
		if testErr != nil || exists {
			return nil, fmt.Errorf("чтение clientsTable: %w", err)
		}
		return clientsFromPeers(srv)
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
	params, err := parseServerConfig(output)
	if err != nil {
		return nil, err
	}
	// Считаем здесь, а не в parseServerConfig: MTU HOP-туннеля видно только с
	// сервера, а парсер обязан оставаться чистой функцией для тестов.
	params.ClientMTU = ClientMTU(params, endpointIsIPv6(srv.EndpointHost()), DetectHopMTU(srv))
	return params, nil
}

// parseServerConfig разбирает текст awg0.conf. Вынесен из ReadServerConfig,
// чтобы покрываться тестами без SSH.
//
// Параметры обфускации распознаются по принципу blacklist: всё, что в
// [Interface] не является служебным ключом awg-quick (reservedInterfaceKeys), —
// параметр AmneziaWG, и он зеркалится в клиентский конфиг как есть. Так новая
// версия протокола (3.0, 4.0, …) поддерживается без правок кода.
func parseServerConfig(output string) (*ServerParams, error) {
	params := &ServerParams{AWGParams: make(map[string]string)}

	var curPeer *PeerBlock
	flushPeer := func() {
		if curPeer == nil {
			return
		}
		params.Peers = append(params.Peers, *curPeer)
		if curPeer.AllowedIPs != "" {
			params.PeerAllowedIPs = append(params.PeerAllowedIPs, curPeer.AllowedIPs)
		}
		curPeer = nil
	}

	// Имена секций и ключей сравниваем без учёта регистра: парсер awg-quick
	// разбирает конфиг с `shopt -s nocasematch`, поэтому `postup = ...` для него
	// служебный ключ. При blacklist-подходе регистрозависимое сравнение приняло
	// бы такую строку за параметр обфускации и скопировало бы её клиенту.
	section := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "[interface]":
			flushPeer()
			section = "interface"
			continue
		case "[peer]":
			flushPeer()
			section = "peer"
			curPeer = &PeerBlock{}
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
		lkey := strings.ToLower(key)

		switch section {
		case "interface":
			switch lkey {
			case "privatekey":
				params.PrivateKey = val
			case "address":
				params.Address = val
			case "listenport":
				params.ListenPort = val
			case "dns":
				params.DNS = val
			default:
				if reservedInterfaceKeys[lkey] {
					continue
				}
				// Известные параметры кладём под каноническим именем из
				// awgParamSpecs — иначе `jc = 4` не нашёлся бы в clientParamOrder
				// и молча выпал бы из клиентского конфига. Незнакомые сохраняют
				// написание сервера.
				name, known := awgParamCanonical[lkey]
				if !known {
					name = key
				}
				if _, dup := params.AWGParams[name]; !dup && !known {
					// Параметр из версии протокола, которой бот ещё не знает.
					// Зеркалим его всё равно — но пусть будет виден в журнале.
					log.Printf("AWG: неизвестный параметр %q в [Interface] — копирую в клиентский конфиг как есть", key)
					params.ExtraParamOrder = append(params.ExtraParamOrder, name)
				}
				params.AWGParams[name] = val
			}
		case "peer":
			if curPeer == nil {
				continue
			}
			switch lkey {
			case "publickey":
				curPeer.PublicKey = val
			case "allowedips":
				curPeer.AllowedIPs = val
			}
		}
	}
	flushPeer()

	params.Version = deriveConfigVersion(params)

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
		markUsed(c.UserData.AllowedIPs) // dual-stack: "10.8.0.5/32, fd00:a::5/128"
	}

	// Выделение в реальной подсети сервера.
	if srvParams != nil && srvParams.Address != "" {
		serverIP, ipnet, err := net.ParseCIDR(firstIPv4CIDR(srvParams.Address))
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

// firstIPv4CIDR выбирает IPv4-часть строки Address, которая может быть
// dual-stack: "10.8.0.1/22, 2a01:db8::1/64" — именно так её пишет buildServerConf
// при включённом IPv6. Без этого net.ParseCIDR падает на всей строке, и
// выделение адреса молча срывается в запасной пул 10.8.0.0/22.
func firstIPv4CIDR(addr string) string {
	for _, part := range strings.Split(addr, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.Contains(part, ":") {
			continue
		}
		return part
	}
	return ""
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

// ipv6Used — множество занятых IPv6-адресов: канонические строки (net.IP.String)
// для CIDR-режимов и сырые нижнерегистровые для legacy-режима, который сравнивает
// адреса как строки.
type ipv6Used struct {
	canonical map[string]bool
	raw       map[string]bool
}

func (u ipv6Used) mark(list string) {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, ":") {
			continue
		}
		raw := strings.Split(part, "/")[0]
		u.raw[strings.ToLower(raw)] = true
		if ip := net.ParseIP(raw); ip != nil {
			u.canonical[ip.String()] = true
		}
	}
}

// collectUsedIPv6 собирает занятые IPv6 из clientsTable, из реальных
// [Peer]-секций конфига и из адреса самого AWG-интерфейса.
//
// Пиры нужны по той же причине, что и для IPv4: клиенты, созданные приложением
// Amnezia или вручную, в clientsTable могут отсутствовать. Адрес интерфейса —
// потому что при /48 и /56 пул клиентов совпадает с подсетью сервера, и без
// этого первый же клиент получал бы собственный адрес сервера.
func collectUsedIPv6(clients []ClientEntry, srvParams *ServerParams) ipv6Used {
	used := ipv6Used{canonical: map[string]bool{}, raw: map[string]bool{}}
	for _, c := range clients {
		used.mark(c.UserData.AllowedIPs)
	}
	if srvParams != nil {
		for _, p := range srvParams.PeerAllowedIPs {
			used.mark(p)
		}
		used.mark(srvParams.Address)
	}
	return used
}

// allocateIPv6 allocates the next free IPv6 address or subnet from a pool.
//
// Modes based on CIDR prefix length:
//   - /96: allocate /112 subnets (each client gets prefix::N:0/112, addr prefix::N:1)
//   - /112 or larger: allocate individual addresses within the CIDR
//   - bare prefix (no /): legacy string-based allocation
func allocateIPv6(clients []ClientEntry, subnetCIDR string, srvParams *ServerParams) (*IPv6AllocResult, error) {
	used := collectUsedIPv6(clients, srvParams)

	// Try CIDR parsing
	if strings.Contains(subnetCIDR, "/") {
		_, ipNet, err := net.ParseCIDR(subnetCIDR)
		if err == nil {
			ones, _ := ipNet.Mask.Size()

			// /96 pool → allocate /112 subnets per client
			if ones <= 96 {
				return allocateIPv6Subnet112(ipNet, used.canonical)
			}

			// /112 or tighter → allocate individual addresses
			return allocateIPv6Address(ipNet, used.canonical, subnetCIDR)
		}
	}

	// Fallback: bare prefix like "fd00:a::"
	return allocateIPv6Legacy(used, subnetCIDR)
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

// allocateIPv6Legacy handles bare prefix strings like "fd00:a::".
func allocateIPv6Legacy(used ipv6Used, subnetCIDR string) (*IPv6AllocResult, error) {
	vpnPrefix := strings.TrimSuffix(subnetCIDR, "::")
	if !strings.HasSuffix(vpnPrefix, ":") {
		vpnPrefix += "::"
	} else {
		vpnPrefix += ":"
	}

	for i := 2; i <= 0xFFFE; i++ {
		ip := fmt.Sprintf("%s%x", vpnPrefix, i)
		if !used.raw[strings.ToLower(ip)] {
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

	dns1, dns2 := resolveClientDNS(srv, srvParams)

	// IPv6 allocation
	clientIPv6 := ""
	clientIPv6Mask := "128"
	allowedIPs := newIP + "/32"
	if srv.IPv6Subnet != "" {
		alloc, ipv6Err := allocateIPv6(clients, srv.IPv6Subnet, srvParams)
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

	// Режим «случайный порт»: клиент шлёт трафик на свой порт, DNAT на сервере
	// приводит его к порту AWG. Сам сервер при этом ничего не меняет — только
	// Endpoint в клиентском конфиге.
	endpointPort := srvParams.ListenPort
	clientPort := 0
	if srv.RandomPort {
		if port, portErr := pickClientPort(srv); portErr != nil {
			log.Printf("AWG (%s): случайный порт не выбран, отдаю штатный %s: %v", srv.Name, endpointPort, portErr)
		} else {
			clientPort = port
			endpointPort = strconv.Itoa(port)
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
			ClientPort:      clientPort,
		},
	}
	clients = append(clients, newEntry)

	if err := writeClientsTable(srv, clients); err != nil {
		return "", "", err
	}

	if err := reloadInterface(srv, false); err != nil {
		return "", "", err
	}

	// Build client config (AmneziaWG format).
	// Endpoint берётся из EndpointHost() — публичный IPv4, даже если SSH идёт по IPv6.
	endpointHost := srv.EndpointHost()
	clientConf = BuildClientConfig(privKey, psk, newIP, endpointHost, endpointPort, dns1, dns2, srvParams, clientIPv6, clientIPv6Mask)

	// Build AmneziaVPN URI (non-fatal on error)
	vpnURI, _, vpnErr := BuildAmneziaVPNURI(privKey, pubKey, psk, newIP, endpointHost, endpointPort, srv.Name, dns1, dns2, srvParams, clientIPv6, clientIPv6Mask)
	if vpnErr != nil {
		log.Printf("AmneziaVPN URI build failed: %v", vpnErr)
	}

	return clientConf, vpnURI, nil
}

// reloadInterface перечитывает конфиг интерфейса.
//
// full=true — полный рестарт сервиса: он нужен, когда из конфига УДАЛЯЛИСЬ
// параметры, потому что `awg syncconf` умеет добавлять и менять их, но не
// снимать. Для добавления и удаления пиров хватает syncconf.
func reloadInterface(srv ServerConfig, full bool) error {
	iface := srv.IfaceName()

	if full {
		if srv.Mode == "native" {
			if _, err := SSHRun(srv, fmt.Sprintf("systemctl restart awg-quick@%s", iface)); err != nil {
				return fmt.Errorf("рестарт интерфейса: %w", err)
			}
			return nil
		}
		cmd := fmt.Sprintf("bash -c 'awg-quick down %s; awg-quick up %s'", iface, iface)
		if _, err := execAWG(srv, cmd); err != nil {
			return fmt.Errorf("рестарт интерфейса: %w", err)
		}
		return nil
	}

	// bash нужен для process substitution <(...)
	cmd := fmt.Sprintf("bash -c 'awg syncconf %s <(awg-quick strip %s)'", iface, confPath(srv))
	if _, err := execAWG(srv, cmd); err != nil {
		return fmt.Errorf("перезагрузка интерфейса: %w", err)
	}
	return nil
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
	removeCmd := fmt.Sprintf("awg set %s peer %s remove", srv.IfaceName(), pubKey)
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
	output, err := execAWG(srv, fmt.Sprintf("awg show %s", srv.IfaceName()))
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
	output, err := execAWG(srv, fmt.Sprintf("awg show %s dump", srv.IfaceName()))
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

	// Без явного MTU awg-quick посчитает его сам и промахнётся ровно на S4
	// (см. mtu.go) — каждый пакет данных поедет двумя IP-фрагментами.
	if params.ClientMTU > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", params.ClientMTU))
	}

	// Параметры обфускации копируются с сервера как есть, в детерминированном порядке.
	for _, key := range clientParamOrder(params) {
		sb.WriteString(fmt.Sprintf("%s = %s\n", key, params.AWGParams[key]))
	}

	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", params.PublicKey))
	sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", psk))
	// JoinHostPort оборачивает IPv6-адрес в квадратные скобки; без этого
	// "Endpoint = 2a01:db8::1:51820" неразличим с адресом без порта.
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", net.JoinHostPort(serverIP, serverPort)))
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

// amneziaAWGData — секция "awg" контейнера в конфиге AmneziaVPN.
//
// Параметры обфускации лежат в Params и попадают в JSON плоско, рядом с
// фиксированными полями. Фиксированной структурой их описать нельзя: набор
// параметров задаёт версия протокола на сервере, и каждая новая версия
// (3.0, 4.0, …) требовала бы правки полей.
type amneziaAWGData struct {
	LastConfig      string
	Port            string
	ProtocolVersion string
	SubnetAddress   string
	TransportProto  string
	Params          map[string]string
}

// protocol_version в конфиге AmneziaVPN. Значения — не номер версии протокола
// AWG, а строки, которыми оперирует само приложение (protocolConstants.h:
// awgV1_5 = "1.5", awgV2 = "2", awgV3 = "3.1"). Для всей ветки 3.x приложение
// знает единственное значение — "3.1"; если отдать "2", AmneziaVPN 5.x пометит
// контейнер как устаревший (serverHasOutdatedAwgContainer) и покажет
// «(version 2)», хотя сервер работает на 3.x.
const (
	amneziaProtoV1 = "1"
	amneziaProtoV2 = "2"
	amneziaProtoV3 = "3.1"
)

// amneziaAWGFixedKeys — не-параметрические ключи секции "awg".
var amneziaAWGFixedKeys = map[string]bool{
	"last_config": true, "port": true, "protocol_version": true,
	"subnet_address": true, "transport_proto": true,
}

func (a amneziaAWGData) MarshalJSON() ([]byte, error) {
	m := map[string]string{
		"last_config":      a.LastConfig,
		"port":             a.Port,
		"protocol_version": a.ProtocolVersion,
		"transport_proto":  a.TransportProto,
	}
	if a.SubnetAddress != "" {
		m["subnet_address"] = a.SubnetAddress
	}
	for key, val := range a.Params {
		if amneziaAWGFixedKeys[key] {
			continue
		}
		m[key] = val
	}
	// json.Marshal сортирует ключи map — порядок детерминирован.
	return json.Marshal(m)
}

func (a *amneziaAWGData) UnmarshalJSON(data []byte) error {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	a.Params = make(map[string]string)
	for key, val := range raw {
		switch key {
		case "last_config":
			a.LastConfig = val
		case "port":
			a.Port = val
		case "protocol_version":
			a.ProtocolVersion = val
		case "subnet_address":
			a.SubnetAddress = val
		case "transport_proto":
			a.TransportProto = val
		default:
			a.Params[key] = val
		}
	}
	return nil
}

// BuildAmneziaVPNURI builds a vpn:// URI for AmneziaVPN app.
// clientIPv6 (address, prefix length) — те же необязательные аргументы, что у
// BuildClientConfig: без них конфиг внутри vpn:// вышел бы IPv4-only, хотя
// allowed_ips в нём заявляет ::/0.
func BuildAmneziaVPNURI(privKey, pubKey, psk, clientIP, serverIP, serverPort, serverName, dns1, dns2 string, params *ServerParams, clientIPv6 ...string) (vpnURI string, compressedData []byte, err error) {
	// Работаем с КОПИЕЙ параметров: дописывать I1-I5 прямо в params.AWGParams
	// нельзя — это данные вызывающей стороны, и пустой "I1 = " в клиентском
	// .conf роняет awg-quick. Раньше от этого спасал лишь порядок вызовов в
	// AddPeer (BuildClientConfig до BuildAmneziaVPNURI).
	local := &ServerParams{
		PublicKey:       params.PublicKey,
		ClientMTU:       params.ClientMTU,
		ExtraParamOrder: params.ExtraParamOrder,
		AWGParams:       make(map[string]string, len(params.AWGParams)+5),
	}
	for k, v := range params.AWGParams {
		local.AWGParams[k] = v
	}

	// Тип контейнера — это версия контейнера Amnezia, а не протокола AWG:
	// отдельного amnezia-awg3 в приложении AmneziaVPN нет, поэтому все версии
	// протокола ≥ 2.0 отдаются как amnezia-awg2.
	confVersion := deriveConfigVersion(params)
	containerType := "amnezia-awg"
	protoVersion := amneziaProtoV1
	if versionRank(confVersion) >= versionRank(AWGVersion2) {
		containerType = "amnezia-awg2"
		protoVersion = amneziaProtoV2
		// Приложение AmneziaVPN ожидает ключи I1-I5 в контейнере awg2;
		// если сервер их не задаёт — отдаём пустыми.
		for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
			if _, ok := local.AWGParams[k]; !ok {
				local.AWGParams[k] = ""
			}
		}
	}
	if versionRank(confVersion) >= versionRank(AWGVersion3) {
		protoVersion = amneziaProtoV3
	}

	// Build the full WG+AWG config text
	confText := BuildClientConfig(privKey, psk, clientIP, serverIP, serverPort, dns1, dns2, local, clientIPv6...)

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
		"mtu":                   clientMTUString(local),
		"persistent_keep_alive": "25",
		"allowed_ips":           []string{"0.0.0.0/0", "::/0"},
	}
	// Copy ALL AWG params into last_config (including I1-I5 for v2)
	for _, key := range clientParamOrder(local) {
		lastConfigMap[key] = local.AWGParams[key]
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

	// Duplicate AWG params at container level
	awgData := amneziaAWGData{
		LastConfig:      string(lastConfigBytes),
		Port:            serverPort,
		ProtocolVersion: protoVersion,
		SubnetAddress:   subnetAddr,
		TransportProto:  "udp",
		Params:          make(map[string]string, len(local.AWGParams)),
	}
	for _, key := range clientParamOrder(local) {
		awgData.Params[key] = local.AWGParams[key]
	}
	// Ключи I1-I5 приложение AmneziaVPN ожидает в контейнере всегда, даже
	// пустыми: прежняя структура объявляла их без omitempty, и для серверов
	// AWG 1.0 (где local их не содержит) они иначе исчезли бы из JSON.
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5"} {
		if _, ok := awgData.Params[k]; !ok {
			awgData.Params[k] = ""
		}
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

// DetectedServer — всё, что бот выяснил о сервере за один заход по SSH.
type DetectedServer struct {
	Mode    string // "docker" / "native"
	ConfDir string
	Iface   string
	Version AWGVersionInfo
}

// awgConfDirCandidates — где искать конфиг AWG на нативной установке.
var awgConfDirCandidates = []string{
	defaultNativeDir, // /etc/amnezia/amneziawg
	"/etc/wireguard",
	defaultDockerDir, // /opt/amnezia/awg
}

// awgConfCandidate — найденный на сервере конфиг AWG.
type awgConfCandidate struct {
	Dir             string
	Iface           string
	HasClientsTable bool
}

// detectAWGMode connects via SSH and determines AWG mode (docker/native),
// config directory, interface name and protocol version.
//
// Порядок «docker → native» намеренный: контейнер AmneziaVPN пробуется первым,
// потому что именно там живут реальные клиенты. Native — полноправная
// альтернатива, а не замена.
func detectAWGMode(ip, login, pass string) (*DetectedServer, error) {
	// Name проставляем, иначе SSH-ошибки печатаются с пустым именем сервера.
	tmpSrv := ServerConfig{Name: ip, IP: ip, Login: login, Pass: pass}

	// --- Docker ---
	if out, err := execAWG(tmpSrv, "awg show interfaces"); err == nil {
		det := &DetectedServer{
			Mode:    "docker",
			ConfDir: defaultDockerDir,
			Iface:   pickIface(strings.Fields(out), ""),
		}
		det.Version, _ = detectAWGVersion(withDetected(tmpSrv, det))
		return det, nil
	}

	// --- Native ---
	nativeSrv := tmpSrv
	nativeSrv.Mode = "native"
	out, err := SSHRun(nativeSrv, "awg show interfaces")
	if err != nil {
		return nil, fmt.Errorf("AWG не обнаружен на сервере %s", ip)
	}

	liveIfaces := strings.Fields(out)
	cands := scanAWGConfDirs(nativeSrv)
	best, found := pickAWGConf(cands, liveIfaces)
	if len(liveIfaces) == 0 && !found {
		// Инструменты AWG стоят, но ни интерфейса, ни конфига нет — считаем,
		// что сервер не настроен, и предлагаем установку.
		return nil, fmt.Errorf("AWG не обнаружен на сервере %s", ip)
	}

	det := &DetectedServer{Mode: "native", ConfDir: defaultNativeDir, Iface: pickIface(liveIfaces, "")}
	if found {
		det.ConfDir = best.Dir
		det.Iface = best.Iface
	}
	det.Version, _ = detectAWGVersion(withDetected(nativeSrv, det))
	return det, nil
}

// withDetected возвращает копию srv с уже известными режимом и интерфейсом,
// чтобы последующие команды шли на правильный интерфейс и через нужный транспорт.
func withDetected(srv ServerConfig, det *DetectedServer) ServerConfig {
	srv.Mode = det.Mode
	srv.AWGConfDir = det.ConfDir
	srv.Iface = det.Iface
	return srv
}

// pickIface выбирает интерфейс из вывода `awg show interfaces`: prefer (уже
// настроенный в config.yaml), если он в списке, иначе awg0, иначе первый.
// При пустом списке — prefer, а если он пуст, то дефолт.
func pickIface(ifaces []string, prefer string) string {
	if prefer == "" {
		prefer = defaultIfaceName
	}
	for _, i := range ifaces {
		if i == prefer {
			return i
		}
	}
	for _, i := range ifaces {
		if i == defaultIfaceName {
			return i
		}
	}
	if len(ifaces) > 0 {
		return ifaces[0]
	}
	return prefer
}

// scanAWGConfDirs ищет конфиги AWG в известных директориях ОДНОЙ командой:
// каждая SSH-сессия — это новый Dial, лишние обходятся дорого.
func scanAWGConfDirs(srv ServerConfig) []awgConfCandidate {
	script := fmt.Sprintf(
		`for d in %s; do [ -d "$d" ] || continue; for f in "$d"/*.conf; do [ -f "$f" ] || continue; `+
			`t=no; [ -f "$d/clientsTable" ] && t=yes; echo "$d|$(basename "$f" .conf)|$t"; done; done`,
		strings.Join(awgConfDirCandidates, " "))

	out, err := SSHRun(srv, fmt.Sprintf("sh -c '%s'", script))
	if err != nil {
		return nil
	}
	return parseConfScan(out)
}

// parseConfScan — чистый разбор вывода scanAWGConfDirs ("<dir>|<iface>|yes|no").
func parseConfScan(out string) []awgConfCandidate {
	var cands []awgConfCandidate
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
			continue
		}
		cands = append(cands, awgConfCandidate{
			Dir:             parts[0],
			Iface:           parts[1],
			HasClientsTable: parts[2] == "yes",
		})
	}
	return cands
}

// pickAWGConf выбирает лучшую директорию с конфигом. Приоритет — та, где лежит
// И <iface>.conf поднятого интерфейса, И clientsTable: иначе бот может выбрать
// /etc/wireguard, где clientsTable нет, и ListClients будет каждый раз
// восстанавливать таблицу из [Peer] вместо настоящей.
func pickAWGConf(cands []awgConfCandidate, liveIfaces []string) (awgConfCandidate, bool) {
	if len(cands) == 0 {
		return awgConfCandidate{}, false
	}

	live := make(map[string]bool, len(liveIfaces))
	for _, i := range liveIfaces {
		live[i] = true
	}

	// score: чем больше, тем лучше.
	score := func(c awgConfCandidate) int {
		s := 0
		if c.HasClientsTable {
			s += 4
		}
		if live[c.Iface] {
			s += 2
		}
		if c.Iface == defaultIfaceName {
			s++
		}
		return s
	}

	best := cands[0]
	for _, c := range cands[1:] {
		if score(c) > score(best) {
			best = c
		}
	}
	return best, true
}

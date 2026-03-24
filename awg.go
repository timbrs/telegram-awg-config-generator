package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	containerName  = "amnezia-awg2"
	awgConfPath    = "/opt/amnezia/awg/awg0.conf"
	clientsTabPath = "/opt/amnezia/awg/clientsTable"
	ifaceName      = "awg0"
)

type ClientData struct {
	AllowedIPs      string `json:"allowedIps"`
	ClientName      string `json:"clientName"`
	CreationDate    string `json:"creationDate"`
	DataReceived    string `json:"dataReceived"`
	DataSent        string `json:"dataSent"`
	LatestHandshake string `json:"latestHandshake"`
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
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// writeClientsTable marshals the clients list and writes it to the container
func writeClientsTable(srv ServerConfig, clients []ClientEntry) error {
	if clients == nil {
		clients = []ClientEntry{}
	}
	tableJSON, err := json.Marshal(clients)
	if err != nil {
		return fmt.Errorf("сериализация clientsTable: %w", err)
	}

	// Use base64 to safely transfer JSON through shell
	encoded := base64Encode(tableJSON)
	writeCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > %s'", encoded, clientsTabPath)
	if _, err := dockerExec(srv, writeCmd); err != nil {
		return fmt.Errorf("обновление clientsTable: %w", err)
	}
	return nil
}

func dockerExec(srv ServerConfig, cmd string) (string, error) {
	full := fmt.Sprintf("docker exec %s %s", containerName, cmd)
	return SSHRun(srv, full)
}

func ListClients(srv ServerConfig) ([]ClientEntry, error) {
	output, err := dockerExec(srv, fmt.Sprintf("cat %s", clientsTabPath))
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
	output, err := dockerExec(srv, fmt.Sprintf("cat %s", awgConfPath))
	if err != nil {
		return nil, fmt.Errorf("чтение awg конфига: %w", err)
	}

	params := &ServerParams{AWGParams: make(map[string]string)}
	// Known AWG obfuscation parameter names
	awgKeys := map[string]bool{
		"Jc": true, "Jmin": true, "Jmax": true,
		"S1": true, "S2": true, "S3": true, "S4": true,
		"H1": true, "H2": true, "H3": true, "H4": true,
	}

	lines := strings.Split(output, "\n")
	inInterface := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[Interface]" {
			inInterface = true
			continue
		}
		if line == "[Peer]" {
			break
		}
		if !inInterface || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

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
	}

	// Derive public key from private key
	pubOut, err := dockerExec(srv, fmt.Sprintf("sh -c 'echo %s | awg pubkey'", params.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("получение публичного ключа сервера: %w", err)
	}
	params.PublicKey = strings.TrimSpace(pubOut)

	return params, nil
}

func GenerateKeyPair(srv ServerConfig) (privKey, pubKey, psk string, err error) {
	cmd := `sh -c 'priv=$(awg genkey); pub=$(echo "$priv" | awg pubkey); psk=$(awg genpsk); echo "$priv"; echo "$pub"; echo "$psk"'`
	output, err := dockerExec(srv, cmd)
	if err != nil {
		return "", "", "", fmt.Errorf("генерация ключей: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 3 {
		return "", "", "", fmt.Errorf("неожиданный вывод генерации ключей: %s", output)
	}

	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]), strings.TrimSpace(lines[2]), nil
}

func allocateIP(clients []ClientEntry) (string, error) {
	used := make(map[string]bool)
	for _, c := range clients {
		ip := strings.TrimSuffix(c.UserData.AllowedIPs, "/32")
		used[ip] = true
	}

	// Allocate from 10.8.1.2 to 10.8.1.254 (10.8.1.1 is server)
	for i := 2; i <= 254; i++ {
		ip := fmt.Sprintf("10.8.1.%d", i)
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("нет свободных IP-адресов в подсети 10.8.1.0/24")
}

func AddPeer(srv ServerConfig, name string) (clientConf string, err error) {
	privKey, pubKey, psk, err := GenerateKeyPair(srv)
	if err != nil {
		return "", err
	}

	clients, err := ListClients(srv)
	if err != nil {
		return "", err
	}

	newIP, err := allocateIP(clients)
	if err != nil {
		return "", err
	}

	srvParams, err := ReadServerConfig(srv)
	if err != nil {
		return "", err
	}

	// Append [Peer] block to config via base64 to avoid shell escaping issues
	peerBlock := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", pubKey, psk, newIP)

	encoded := base64Encode([]byte(peerBlock))
	appendCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d >> %s'", encoded, awgConfPath)
	if _, err := dockerExec(srv, appendCmd); err != nil {
		return "", fmt.Errorf("добавление пира в конфиг: %w", err)
	}

	// Update clientsTable
	newEntry := ClientEntry{
		ClientID: pubKey,
		UserData: ClientData{
			AllowedIPs:      newIP + "/32",
			ClientName:      name,
			CreationDate:    "just now",
			DataReceived:    "0 B",
			DataSent:        "0 B",
			LatestHandshake: "never",
		},
	}
	clients = append(clients, newEntry)

	if err := writeClientsTable(srv, clients); err != nil {
		return "", err
	}

	// Reload interface (bash needed for process substitution)
	reloadCmd := fmt.Sprintf("bash -c 'awg syncconf %s <(awg-quick strip %s)'", ifaceName, awgConfPath)
	if _, err := dockerExec(srv, reloadCmd); err != nil {
		return "", fmt.Errorf("перезагрузка интерфейса: %w", err)
	}

	// Build client config
	clientConf = BuildClientConfig(privKey, psk, newIP, srv.IP, srvParams.ListenPort, srvParams)

	return clientConf, nil
}

func removePeerBlock(confText, pubKey string) string {
	lines := strings.Split(confText, "\n")
	var result []string
	skip := false

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])

		if trimmed == "[Peer]" {
			// Look ahead to check if this peer has our pubkey
			block := []string{lines[i]}
			j := i + 1
			found := false
			for j < len(lines) {
				t := strings.TrimSpace(lines[j])
				if t == "[Peer]" || t == "[Interface]" {
					break
				}
				block = append(block, lines[j])
				if strings.HasPrefix(t, "PublicKey") && strings.Contains(t, pubKey) {
					found = true
				}
				j++
			}
			if found {
				skip = true
				i = j - 1
				continue
			}
		}

		if !skip {
			result = append(result, lines[i])
		}
		skip = false
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
	if _, err := dockerExec(srv, removeCmd); err != nil {
		return fmt.Errorf("удаление пира из интерфейса: %w", err)
	}

	// Read config, remove peer block in Go, write back
	confText, err := dockerExec(srv, fmt.Sprintf("cat %s", awgConfPath))
	if err != nil {
		return fmt.Errorf("чтение awg конфига для удаления: %w", err)
	}

	newConf := removePeerBlock(confText, pubKey)

	// Write config back via base64 to avoid shell escaping issues
	confEncoded := base64Encode([]byte(newConf))
	writeConfCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d > %s'", confEncoded, awgConfPath)
	if _, err := dockerExec(srv, writeConfCmd); err != nil {
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
	output, err := dockerExec(srv, fmt.Sprintf("awg show %s", ifaceName))
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
	output, err := dockerExec(srv, fmt.Sprintf("awg show %s dump", ifaceName))
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

func BuildClientConfig(privKey, psk, clientIP, serverIP, serverPort string, params *ServerParams) string {
	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", privKey))
	sb.WriteString(fmt.Sprintf("Address = %s/32\n", clientIP))
	sb.WriteString("DNS = 1.1.1.1, 1.0.0.1\n")

	// Write AWG params in deterministic order
	for _, key := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
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

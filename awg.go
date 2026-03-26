package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
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
		"I1": true, "I2": true, "I3": true, "I4": true, "I5": true,
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

func AddPeer(srv ServerConfig, name string) (clientConf string, vpnURI string, err error) {
	privKey, pubKey, psk, err := GenerateKeyPair(srv)
	if err != nil {
		return "", "", err
	}

	clients, err := ListClients(srv)
	if err != nil {
		return "", "", err
	}

	newIP, err := allocateIP(clients)
	if err != nil {
		return "", "", err
	}

	srvParams, err := ReadServerConfig(srv)
	if err != nil {
		return "", "", err
	}

	// Append [Peer] block to config via base64 to avoid shell escaping issues
	peerBlock := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", pubKey, psk, newIP)

	encoded := base64Encode([]byte(peerBlock))
	appendCmd := fmt.Sprintf("bash -c 'printf %%s %s | base64 -d >> %s'", encoded, awgConfPath)
	if _, err := dockerExec(srv, appendCmd); err != nil {
		return "", "", fmt.Errorf("добавление пира в конфиг: %w", err)
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
		return "", "", err
	}

	// Reload interface (bash needed for process substitution)
	reloadCmd := fmt.Sprintf("bash -c 'awg syncconf %s <(awg-quick strip %s)'", ifaceName, awgConfPath)
	if _, err := dockerExec(srv, reloadCmd); err != nil {
		return "", "", fmt.Errorf("перезагрузка интерфейса: %w", err)
	}

	// Build client config (AmneziaWG format)
	clientConf = BuildClientConfig(privKey, psk, newIP, srv.IP, srvParams.ListenPort, srvParams)

	// Build AmneziaVPN URI (non-fatal on error)
	vpnURI, _, vpnErr := BuildAmneziaVPNURI(privKey, pubKey, psk, newIP, srv.IP, srvParams.ListenPort, srv.Name, srvParams)
	if vpnErr != nil {
		log.Printf("AmneziaVPN URI build failed: %v", vpnErr)
	}

	return clientConf, vpnURI, nil
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
func BuildAmneziaVPNURI(privKey, pubKey, psk, clientIP, serverIP, serverPort, serverName string, params *ServerParams) (vpnURI string, compressedData []byte, err error) {
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
	confText := BuildClientConfig(privKey, psk, clientIP, serverIP, serverPort, params)

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
		DNS1:                 "1.1.1.1",
		DNS2:                 "1.0.0.1",
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

	// Debug: write files
	os.WriteFile("amneziavpn_raw.json", jsonBytes, 0644)
	os.WriteFile("amneziavpn_uri.txt", []byte(uri), 0644)

	return uri, compressed, nil
}

package main

import "testing"

// Конфиг, собранный не Amnezia, а руками или скриптом: имя пира живёт в
// комментарии сразу после [Peer]. Без него clientsTable восстанавливается
// безликим (peer-1..peer-N), и админ в боте не понимает, какой ключ чей.
const handMadeServerConf = `[Interface]
Address = 10.223.23.1/24
ListenPort = 20853
PrivateKey = QGJvdC10ZXN0LXByaXZhdGUta2V5LTMyLWJ5dGVzISE=
MTU = 1420
S4 = 16
PostUp = iptables -A FORWARD -i %i -o %i -j ACCEPT

[Peer]
# admin-laptop
PublicKey = MJnPBGh1YWl0ZXN0cHVia2V5MDAwMDAwMDAwMDAwMDA=
AllowedIPs = 10.223.23.2/32

[Peer]
# client01
PublicKey = Mm5QQmdoMXlXbHRlc3RwdWJrZXkwMDAwMDAwMDAwMDA=
AllowedIPs = 10.223.23.10/32

[Peer]
PublicKey = M25QQmdoMXlXbHRlc3RwdWJrZXkwMDAwMDAwMDAwMDA=
AllowedIPs = 10.223.23.11/32
`

func TestParsePeerNamesFromComments(t *testing.T) {
	params, err := parseServerConfig(handMadeServerConf)
	if err != nil {
		t.Fatalf("парсинг конфига: %v", err)
	}
	if len(params.Peers) != 3 {
		t.Fatalf("пиров: %d, ожидалось 3", len(params.Peers))
	}
	if params.Peers[0].Name != "admin-laptop" {
		t.Errorf("имя первого пира %q, ожидалось admin-laptop", params.Peers[0].Name)
	}
	if params.Peers[1].Name != "client01" {
		t.Errorf("имя второго пира %q, ожидалось client01", params.Peers[1].Name)
	}
	if params.Peers[2].Name != "" {
		t.Errorf("у третьего пира комментария нет, а имя %q", params.Peers[2].Name)
	}

	// Комментарий в [Interface] именем пира стать не должен.
	clients := buildClientsFromPeers(params.Peers)
	if len(clients) != 3 {
		t.Fatalf("клиентов: %d, ожидалось 3", len(clients))
	}
	if clients[0].UserData.ClientName != "admin-laptop" {
		t.Errorf("clientName[0] = %q", clients[0].UserData.ClientName)
	}
	if clients[1].UserData.ClientName != "client01" {
		t.Errorf("clientName[1] = %q", clients[1].UserData.ClientName)
	}
	// Безымянный пир сохраняет прежнюю нумерацию.
	if clients[2].UserData.ClientName != "peer-3" {
		t.Errorf("clientName[2] = %q, ожидалось peer-3", clients[2].UserData.ClientName)
	}
	if clients[1].UserData.AllowedIPs != "10.223.23.10/32" {
		t.Errorf("allowedIps[1] = %q", clients[1].UserData.AllowedIPs)
	}
}

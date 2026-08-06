package main

import "testing"

func TestIsSuperAdmin(t *testing.T) {
	srv := ServerConfig{
		AllowedUIDs: []int64{100, 200, 300},
		ReportUIDs:  []int64{200},
	}
	if !isSuperAdmin(200, srv) {
		t.Error("UID 200 в report_uids должен быть суперадмином")
	}
	if isSuperAdmin(100, srv) {
		t.Error("UID 100 не в report_uids — не суперадмин")
	}
	if isSuperAdmin(999, srv) {
		t.Error("посторонний UID не суперадмин")
	}
}

func clientWithCreator(name string, creator int64) ClientEntry {
	return ClientEntry{
		ClientID: name + "-pub",
		UserData: ClientData{ClientName: name, CreatorUID: creator},
	}
}

func TestFilterVisibleClientsRegularAdmin(t *testing.T) {
	all := []ClientEntry{
		clientWithCreator("old", 0),    // ничей (старый) — виден всем
		clientWithCreator("mine1", 100),
		clientWithCreator("foreign", 200),
		clientWithCreator("mine2", 100),
	}

	vis := filterVisibleClients(all, 100, false)

	// Видны: old, mine1, mine2 (foreign — нет).
	if len(vis) != 3 {
		t.Fatalf("ожидалось 3 видимых ключа, получено %d", len(vis))
	}
	for _, c := range vis {
		if c.UserData.ClientName == "foreign" {
			t.Error("чужой ключ не должен быть виден обычному админу")
		}
	}
	// Перенумерация 1..N по порядку.
	for i, c := range vis {
		if c.ID != i+1 {
			t.Errorf("ключ %q: ожидался ID %d, получен %d", c.UserData.ClientName, i+1, c.ID)
		}
	}
}

func TestFilterVisibleClientsSuperAdmin(t *testing.T) {
	all := []ClientEntry{
		clientWithCreator("old", 0),
		clientWithCreator("a", 100),
		clientWithCreator("b", 200),
	}

	vis := filterVisibleClients(all, 999, true) // суперадмин (даже не создатель)
	if len(vis) != 3 {
		t.Fatalf("суперадмин должен видеть все 3 ключа, получено %d", len(vis))
	}
	if vis[0].ID != 1 || vis[2].ID != 3 {
		t.Errorf("ожидалась перенумерация 1..3, получено %d..%d", vis[0].ID, vis[2].ID)
	}
}

func TestFilterVisibleClientsOnlyOwn(t *testing.T) {
	all := []ClientEntry{
		clientWithCreator("a", 200),
		clientWithCreator("b", 300),
	}
	vis := filterVisibleClients(all, 100, false)
	if len(vis) != 0 {
		t.Errorf("у админа нет своих/ничьих ключей — ожидалось 0, получено %d", len(vis))
	}
}

func TestClientByNumberOnPage(t *testing.T) {
	page := []ClientEntry{
		{ClientID: "x", UserData: ClientData{ClientName: "x"}, ID: 3},
		{ClientID: "y", UserData: ClientData{ClientName: "y"}, ID: 2},
		{ClientID: "z", UserData: ClientData{ClientName: "z"}, ID: 1},
	}
	if c := clientByNumberOnPage(page, 2); c == nil || c.ClientID != "y" {
		t.Errorf("ожидался клиент y по номеру 2, получено %v", c)
	}
	if c := clientByNumberOnPage(page, 9); c != nil {
		t.Error("несуществующий номер должен дать nil")
	}
}

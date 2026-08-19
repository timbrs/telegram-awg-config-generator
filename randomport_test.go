package main

import (
	"math/rand"
	"strings"
	"testing"
)

func TestParsePortRange(t *testing.T) {
	lo, hi, err := parsePortRange("20000-32767")
	if err != nil || lo != 20000 || hi != 32767 {
		t.Errorf("parsePortRange(20000-32767) = (%d, %d, %v)", lo, hi, err)
	}

	bad := []string{
		"",
		"20000",
		"20000-",
		"abc-32767",
		"500-32767",   // ниже 1024
		"20000-70000", // выше 65535
		"20000-20500", // не помещаются все блоки
	}
	for _, spec := range bad {
		if _, _, err := parsePortRange(spec); err == nil {
			t.Errorf("parsePortRange(%q) должен был вернуть ошибку", spec)
		}
	}
}

// Блоки должны быть свободны, не пересекаться и лежать внутри пула — иначе DNAT
// уведёт в туннель трафик чужого сервиса.
func TestPickPortBlocks(t *testing.T) {
	busy := map[int]bool{20050: true, 24999: true, 31000: true}
	r := rand.New(rand.NewSource(1))

	blocks := pickPortBlocks(20000, 32767, busy, portBlockCount, portBlockSize, r)
	if len(blocks) != portBlockCount {
		t.Fatalf("ожидалось %d блоков, получено %d", portBlockCount, len(blocks))
	}

	seen := make(map[int]bool)
	prevHi := 0
	for _, b := range blocks {
		if b.Hi-b.Lo+1 != portBlockSize {
			t.Errorf("блок %s не размера %d", b, portBlockSize)
		}
		if b.Lo < 20000 || b.Hi > 32767 {
			t.Errorf("блок %s вышел за пул 20000-32767", b)
		}
		if b.Lo <= prevHi {
			t.Errorf("блоки пересекаются или не отсортированы: %s после порта %d", b, prevHi)
		}
		prevHi = b.Hi
		for p := b.Lo; p <= b.Hi; p++ {
			if busy[p] {
				t.Errorf("блок %s содержит занятый порт %d", b, p)
			}
			if seen[p] {
				t.Errorf("порт %d попал в два блока", p)
			}
			seen[p] = true
		}
	}
}

// Разные запуски должны давать разные блоки — иначе «случайный порт» будет
// одинаковым на всех серверах.
func TestPickPortBlocksVaries(t *testing.T) {
	a := pickPortBlocks(20000, 32767, nil, portBlockCount, portBlockSize, rand.New(rand.NewSource(1)))
	b := pickPortBlocks(20000, 32767, nil, portBlockCount, portBlockSize, rand.New(rand.NewSource(2)))
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("блоки не выбраны")
	}
	if strings.Join(blockSpecs(a), ",") == strings.Join(blockSpecs(b), ",") {
		t.Error("два независимых выбора дали одинаковые блоки")
	}
}

// Тесный пул: свободных слотов ровно столько, сколько нужно.
func TestPickPortBlocksTightPool(t *testing.T) {
	lo, hi := 20000, 20000+portBlockSize*portBlockCount-1
	blocks := pickPortBlocks(lo, hi, nil, portBlockCount, portBlockSize, rand.New(rand.NewSource(3)))
	if len(blocks) != portBlockCount {
		t.Fatalf("в тесном пуле ожидалось %d блоков, получено %d", portBlockCount, len(blocks))
	}

	// А если половина слотов занята — выбираем сколько получится, а не молча ноль.
	busy := map[int]bool{}
	for i := 0; i < portBlockCount/2; i++ {
		busy[lo+i*portBlockSize] = true
	}
	partial := pickPortBlocks(lo, hi, busy, portBlockCount, portBlockSize, rand.New(rand.NewSource(4)))
	if len(partial) != portBlockCount-portBlockCount/2 {
		t.Errorf("ожидалось %d свободных блоков, получено %d", portBlockCount-portBlockCount/2, len(partial))
	}
}

// Переприменение режима не должно менять блоки: Endpoint уже выданных ключей
// указывает на порты из них.
func TestUsableBlocks(t *testing.T) {
	blocks := []portBlock{{20000, 20099}, {25000, 25099}, {40000, 40099}}
	busy := map[int]bool{25050: true}

	got := usableBlocks(blocks, 20000, 32767, busy)
	if len(got) != 1 || got[0].Lo != 20000 {
		t.Errorf("ожидался только блок 20000-20099, получено %v", blockSpecs(got))
	}
	// 25000-25099 отпал из-за занятого порта, 40000-40099 — как вышедший за пул.
}

func TestRandomPortFromBlocks(t *testing.T) {
	blocks := []portBlock{{20000, 20099}, {25000, 25099}}
	busy := map[int]bool{}
	for p := 20000; p <= 20099; p++ {
		busy[p] = true // весь первый блок занят
	}

	r := rand.New(rand.NewSource(7))
	for i := 0; i < 50; i++ {
		port := randomPortFromBlocks(blocks, busy, r)
		if port < 25000 || port > 25099 {
			t.Fatalf("порт %d не из свободного блока 25000-25099", port)
		}
	}

	// Свободных портов не осталось вовсе.
	for p := 25000; p <= 25099; p++ {
		busy[p] = true
	}
	if port := randomPortFromBlocks(blocks, busy, r); port != 0 {
		t.Errorf("при полностью занятых блоках ожидался 0, получено %d", port)
	}
}

func TestParseListeningUDPPorts(t *testing.T) {
	out := `UNCONN 0      0            0.0.0.0:51820      0.0.0.0:*
UNCONN 0      0          127.0.0.1:53         0.0.0.0:*
UNCONN 0      0               [::]:51821          [::]:*
мусор
`
	busy := parseListeningUDPPorts(out)
	for _, port := range []int{51820, 53, 51821} {
		if !busy[port] {
			t.Errorf("порт %d не распознан как занятый", port)
		}
	}
	if len(busy) != 3 {
		t.Errorf("ожидалось 3 занятых порта, получено %d: %v", len(busy), busy)
	}
}

// В docker правило обязано указывать на адрес контейнера: цепочка стоит раньше
// DOCKER, а DNAT терминален — докеровский проброс уже не отработает.
func TestBuildRandomPortScriptDocker(t *testing.T) {
	script := buildRandomPortScript(randomPortParams{
		Blocks:    []portBlock{{20000, 20099}, {25000, 25099}},
		NetIface:  "eth0",
		AWGPort:   51820,
		Container: containerName,
	})

	mustContain := []string{
		"BLOCKS='20000-20099 25000-25099'",
		"NET_IFACE='eth0'",
		"AWG_PORT=51820",
		"CONTAINER='" + containerName + "'",
		"docker inspect",
		"-j DNAT --to-destination",
		"-j RETURN", // занятые порты пропускаются мимо DNAT
		"iptables -t nat -I PREROUTING 1",
	}
	for _, s := range mustContain {
		if !strings.Contains(script, s) {
			t.Errorf("скрипт не содержит %q\n\n%s", s, script)
		}
	}
}

func TestBuildRandomPortScriptNative(t *testing.T) {
	script := buildRandomPortScript(randomPortParams{
		Blocks:  []portBlock{{30000, 30099}},
		AWGPort: 51820,
	})

	if !strings.Contains(script, "-j REDIRECT --to-ports") {
		t.Error("для native ожидался REDIRECT на локальный порт")
	}
	if !strings.Contains(script, "CONTAINER=''") {
		t.Error("для native контейнер должен быть пустым")
	}
	// Без заданного интерфейса скрипт определяет его сам.
	if !strings.Contains(script, "ip route get 1.1.1.1") {
		t.Error("скрипт должен уметь определить внешний интерфейс сам")
	}
	// stop снимает и правило из PREROUTING, и саму цепочку.
	for _, s := range []string{"iptables -t nat -D PREROUTING", "iptables -t nat -X"} {
		if !strings.Contains(script, s) {
			t.Errorf("скрипт не умеет снимать правила: нет %q", s)
		}
	}
}

func TestPortBlocksRoundTrip(t *testing.T) {
	specs := []string{"20000-20099", "мусор", "25000-25099"}
	blocks := parsePortBlocks(specs)
	if len(blocks) != 2 {
		t.Fatalf("ожидалось 2 разобранных блока, получено %d", len(blocks))
	}
	got := blockSpecs(blocks)
	if got[0] != "20000-20099" || got[1] != "25000-25099" {
		t.Errorf("blockSpecs = %v", got)
	}
}

// Пул по умолчанию должен быть валидным сам по себе, иначе режим не включится
// на сервере, где диапазон не задан руками.
func TestDefaultPortRangeIsValid(t *testing.T) {
	lo, hi, err := parsePortRange(defaultPortRange)
	if err != nil {
		t.Fatalf("defaultPortRange невалиден: %v", err)
	}
	if blocks := pickPortBlocks(lo, hi, nil, portBlockCount, portBlockSize, rand.New(rand.NewSource(5))); len(blocks) != portBlockCount {
		t.Errorf("из пула по умолчанию нарезалось %d блоков вместо %d", len(blocks), portBlockCount)
	}

	srv := ServerConfig{}
	if srv.PortRange() != defaultPortRange {
		t.Errorf("PortRange() без настройки = %q, ожидалось %q", srv.PortRange(), defaultPortRange)
	}
}

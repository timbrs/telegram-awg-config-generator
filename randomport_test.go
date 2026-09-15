package main

import (
	"math/rand"
	"net/netip"
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

// serverGBlocks — те самые 20 блоков по 150 портов, что стоят на serverG.
func serverGBlocks() []portBlock {
	return []portBlock{
		{20150, 20299}, {21500, 21649}, {21800, 21949}, {22700, 22849},
		{23450, 23599}, {23750, 23899}, {25250, 25399}, {25550, 25699},
		{26300, 26449}, {26450, 26599}, {26600, 26749}, {27050, 27199},
		{27500, 27649}, {27650, 27799}, {28400, 28549}, {30050, 30199},
		{31250, 31399}, {32150, 32299}, {32300, 32449}, {32450, 32599},
	}
}

// Набор клиента: 100-600 портов, все внутри блоков сервера, по кусочку в
// каждом блоке — размазать по максимуму и есть смысл затеи.
func TestPickClientPortRanges(t *testing.T) {
	blocks := serverGBlocks()
	r := rand.New(rand.NewSource(3))

	for i := 0; i < 200; i++ {
		ranges := pickClientPortRanges(blocks, r)
		if len(ranges) != len(blocks) {
			t.Fatalf("задействовано %d блоков из %d", len(ranges), len(blocks))
		}
		total := 0
		for _, sub := range ranges {
			if sub.Hi < sub.Lo {
				t.Fatalf("перевёрнутый диапазон %s", sub)
			}
			total += sub.Hi - sub.Lo + 1
			inside := false
			for _, b := range blocks {
				if sub.Lo >= b.Lo && sub.Hi <= b.Hi {
					inside = true
					break
				}
			}
			if !inside {
				t.Fatalf("кусок %s вышел за блоки сервера", sub)
			}
		}
		if total < clientPortsMin || total > clientPortsMax {
			t.Fatalf("выдано %d портов, ожидалось %d-%d", total, clientPortsMin, clientPortsMax)
		}
	}
}

// Два ключа подряд не должны получить один и тот же набор — иначе смысла в
// случайности нет.
func TestPickClientPortRangesVaries(t *testing.T) {
	blocks := serverGBlocks()
	r := rand.New(rand.NewSource(11))
	first := clientPortsSpec(pickClientPortRanges(blocks, r))
	same := 0
	for i := 0; i < 20; i++ {
		if clientPortsSpec(pickClientPortRanges(blocks, r)) == first {
			same++
		}
	}
	if same > 0 {
		t.Errorf("%d из 20 наборов совпали с первым", same)
	}
}

// Один блок меньше минимального куска — берём его целиком, а не вылезаем за край.
func TestPickClientPortRangesTinyBlock(t *testing.T) {
	blocks := []portBlock{{20000, 20003}, {21000, 21149}}
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 50; i++ {
		ranges := pickClientPortRanges(blocks, r)
		if ranges[0].Lo != 20000 || ranges[0].Hi != 20003 {
			t.Fatalf("маленький блок взят не целиком: %s", ranges[0])
		}
	}
	if pickClientPortRanges(nil, r) != nil {
		t.Error("без блоков сервера набор должен быть пустым")
	}
}

// Порт Endpoint обязан лежать в наборе: клиент без awg-proxy знает только его.
func TestEndpointPortComesFromClientSet(t *testing.T) {
	blocks := serverGBlocks()
	r := rand.New(rand.NewSource(17))
	for i := 0; i < 100; i++ {
		ranges := pickClientPortRanges(blocks, r)
		port := randomPortFromBlocks(ranges, nil, r)
		inSet := false
		for _, sub := range ranges {
			if sub.contains(port) {
				inSet = true
				break
			}
		}
		if !inSet {
			t.Fatalf("порт Endpoint %d вне набора %s", port, clientPortsSpec(ranges))
		}
	}
}

// Формат строки — ровно тот, что разбирает awg-proxy в AWG_REMOTE.
func TestClientPortsSpec(t *testing.T) {
	spec := clientPortsSpec([]portBlock{{20150, 20179}, {21500, 21529}})
	if spec != "20150-20179,21500-21529" {
		t.Errorf("clientPortsSpec = %q", spec)
	}
	if clientPortsSpec(nil) != "" {
		t.Error("пустой набор должен давать пустую строку")
	}
}

// serverD до 15.09.2026: REDIRECT соседнего AWG (awg_hub, :51821) стоял выше цепочки
// бота и забирал блок 20800-20899 — 8 ключей бота так ни разу и не подключились.
const iptablesServerDBefore = `# Generated by iptables-save
*nat
:PREROUTING ACCEPT [0:0]
:AWGRANDOM - [0:0]
:DOCKER - [0:0]
-A PREROUTING -i eth0 -p udp -m udp --dport 20000:20999 -j REDIRECT --to-ports 51821
-A PREROUTING -i eth0 -p udp -j AWGRANDOM
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A AWGRANDOM -p udp -m udp --dport 38418 -j RETURN
-A AWGRANDOM -p udp -m udp --dport 20800:20899 -j DNAT --to-destination 172.29.172.2:38418
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i amn0 -p udp -m udp --dport 38418 -j DNAT --to-destination 172.29.172.2:38418
-A DOCKER ! -i br-web -p tcp -m tcp --dport 443 -m comment --comment "nginx https" -j DNAT --to-destination 172.18.0.3:443
COMMIT
# Generated by ip6tables-save
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i eth0 -p udp -m udp --dport 20000:20999 -j REDIRECT --to-ports 51821
COMMIT
`

// Чужой REDIRECT в другой сервис — перехват; свои правила, docker-проброс самого AWG
// и TCP — нет. Пересечение с блоком бота должно быть названо явно.
func TestParseIptablesNATCapturesServerD(t *testing.T) {
	caps := parseIptablesNATCaptures(iptablesServerDBefore, 38418, nil)
	set := capturedPortSet(caps)
	for _, p := range []int{20000, 20863, 20999} {
		if !set[p] {
			t.Errorf("порт %d под REDIRECT :51821 не распознан как чужой перехват", p)
		}
	}
	for _, p := range []int{19999, 21000, 38418, 443} {
		if set[p] {
			t.Errorf("порт %d ошибочно считается чужим перехватом", p)
		}
	}

	conflicts := blockConflicts([]portBlock{{20800, 20899}, {23500, 23599}}, caps)
	if len(conflicts) != 1 {
		t.Fatalf("ожидалось одно пересечение (v4 и v6 — одно и то же), получено %v", conflicts)
	}
	if !strings.Contains(conflicts[0], "20800-20899") || !strings.Contains(conflicts[0], "REDIRECT :51821") {
		t.Errorf("пересечение описано невнятно: %q", conflicts[0])
	}
}

// serverC: широкий DNAT всего 20000-60000 в ТОТ ЖЕ контейнер — не конфликт; а для
// другого AWG тот же DNAT — перехват, но без портов, которые цепочка возвращает (RETURN).
func TestParseIptablesNATCapturesSameAWG(t *testing.T) {
	save := `*nat
:PREROUTING ACCEPT [0:0]
:AWGRANDOM - [0:0]
:AWG_MULTIPORT - [0:0]
-A PREROUTING -i ens3 -p udp -j AWGRANDOM
-A PREROUTING -d 203.0.113.10/32 -i ens3 -p udp -m udp --dport 20000:60000 -j AWG_MULTIPORT
-A AWG_MULTIPORT -p udp -m multiport --dports 37400,37581,45500,48825,51821,51822,51823,59623 -j RETURN
-A AWG_MULTIPORT -p udp -j DNAT --to-destination 172.29.172.2:37581
COMMIT
`
	ours := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8:ffff::23dd")}
	for _, addrs := range [][]netip.Addr{nil, ours} {
		if caps := parseIptablesNATCaptures(save, 37581, addrs); len(caps) != 0 {
			t.Errorf("DNAT в тот же AWG принят за чужой перехват: %v", caps)
		}

		set := capturedPortSet(parseIptablesNATCaptures(save, 51820, addrs))
		if !set[30000] || !set[20000] || !set[60000] {
			t.Error("DNAT в другой AWG должен перехватывать весь вход в цепочку")
		}
		for _, p := range []int{37581, 51821, 19999, 60001} {
			if set[p] {
				t.Errorf("порт %d не должен считаться перехваченным (RETURN или вне входа в цепочку)", p)
			}
		}
	}
	// Вход в цепочку ограничен адресом сервера: для другого адреса перехвата нет.
	if caps := parseIptablesNATCaptures(save, 51820, []netip.Addr{netip.MustParseAddr("10.0.0.1")}); len(caps) != 0 {
		t.Errorf("-d чужого адреса не должен давать перехват: %v", caps)
	}
}

// serverC: в ip6tables DNAT 1:1 для /128 роутеров (NAT66) — без порта и протокола.
// Пакеты клиентов на адрес сервера они не трогают; без отсечки по адресу весь пул
// выглядел бы перехваченным, и бот не смог бы выбрать ни одного блока.
func TestParseIptablesNATCapturesNAT66(t *testing.T) {
	save := `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -d 2001:db8:ffff::1f9/128 -j DNAT --to-destination fd6a:6::2
-A PREROUTING -d 2001:db8:ffff::1df/128 -j DNAT --to-destination fd6a:6::3
COMMIT
`
	srv := ServerConfig{IP: "203.0.113.10", IPv6Host: "[2001:db8:ffff::23dd]", EndpointIP: "не адрес"}
	ours := serverAddrs(srv)
	if len(ours) != 2 {
		t.Fatalf("serverAddrs = %v, ожидалось 2 адреса", ours)
	}
	if caps := parseIptablesNATCaptures(save, 37581, ours); len(caps) != 0 {
		t.Errorf("NAT66 1:1 чужих адресов принят за перехват портов сервера: %v", caps)
	}
	blocks := chooseRandomPortBlocks(20000, 32767, nil, nil,
		capturedPortSet(parseIptablesNATCaptures(save, 37581, ours)), rand.New(rand.NewSource(1)))
	if len(blocks) != portBlockCount {
		t.Errorf("при NAT66 рядом должно выбираться %d блоков, выбрано %d", portBlockCount, len(blocks))
	}

	// А DNAT всего трафика на сам адрес сервера — перехват всех портов.
	self := []netip.Addr{netip.MustParseAddr("2001:db8:ffff::1f9")}
	if set := capturedPortSet(parseIptablesNATCaptures(save, 37581, self)); !set[20000] || !set[65535] {
		t.Error("DNAT всего трафика на адрес сервера должен считаться перехватом")
	}
}

func TestParseNftNATCaptures(t *testing.T) {
	text := `		iifname "eth0" udp dport 20000-20999 counter packets 2 bytes 104 redirect to :51821
		udp dport 20800-20899 counter packets 2 bytes 104 dnat to 172.29.172.2:38418
		meta l4proto udp udp dport 443 counter packets 26758 bytes 29880641 redirect to :27015
		udp dport { 5000, 6000-6010 } dnat ip to 10.0.0.5:9999
		udp dport != 53 redirect to :1
`
	set := capturedPortSet(parseNftNATCaptures(text, 38418, nil))
	for _, p := range []int{20000, 20999, 443, 5000, 6005} {
		if !set[p] {
			t.Errorf("порт %d не распознан как чужой перехват", p)
		}
	}
	for _, p := range []int{21000, 5001, 53, 1} {
		if set[p] {
			t.Errorf("порт %d ошибочно считается перехваченным", p)
		}
	}
	// 20800-20899 -> :38418 — это сам AWG, поэтому отдельного перехвата у блока нет:
	// порты блока перехвачены только правилом :51821
	for _, c := range parseNftNATCaptures(text, 38418, nil) {
		if strings.Contains(c.Target, "38418") {
			t.Errorf("правило в сам AWG принято за чужое: %v", c)
		}
	}

	// Условие на адрес назначения: чужой адрес — не перехват, адрес сервера — перехват.
	daddr := `		ip daddr 127.0.0.1 udp dport 5353 dnat to 10.0.0.9:53
		ip daddr 198.51.100.20 udp dport 7000 redirect to :7001
`
	ours := []netip.Addr{netip.MustParseAddr("198.51.100.20")}
	set = capturedPortSet(parseNftNATCaptures(daddr, 38418, ours))
	if set[5353] || !set[7000] {
		t.Errorf("отсечка по daddr: 5353=%v (ждали false), 7000=%v (ждали true)", set[5353], set[7000])
	}
}

// Новые блоки никогда не ложатся под чужой перехват; старый блок под перехватом
// сохраняется — на нём выданные ключи, выкинуть его значит отрезать клиентов.
func TestChooseRandomPortBlocksAvoidsForeign(t *testing.T) {
	foreign := map[int]bool{}
	for p := 20000; p <= 20999; p++ {
		foreign[p] = true
	}
	for p := 25000; p <= 25999; p++ {
		foreign[p] = true
	}
	for seed := int64(1); seed <= 30; seed++ {
		blocks := chooseRandomPortBlocks(20000, 32767, nil, nil, foreign, rand.New(rand.NewSource(seed)))
		if len(blocks) != portBlockCount {
			t.Fatalf("seed %d: ожидалось %d блоков, получено %d", seed, portBlockCount, len(blocks))
		}
		for _, b := range blocks {
			if b.Hi >= 20000 && b.Lo <= 20999 || b.Hi >= 25000 && b.Lo <= 25999 {
				t.Fatalf("seed %d: блок %s лёг под чужой перехват", seed, b)
			}
		}
	}

	kept := chooseRandomPortBlocks(20000, 32767, []portBlock{{20800, 20899}}, nil, foreign, rand.New(rand.NewSource(1)))
	if len(kept) != portBlockCount || kept[0] != (portBlock{20800, 20899}) {
		t.Fatalf("старый блок 20800-20899 должен сохраниться первым, получено %v", blockSpecs(kept))
	}
	for _, b := range kept[1:] {
		if b.Hi >= 20000 && b.Lo <= 20999 || b.Hi >= 25000 && b.Lo <= 25999 {
			t.Errorf("добранный блок %s лёг под чужой перехват", b)
		}
	}
}

func TestBlocksWithout(t *testing.T) {
	blocks := []portBlock{{20800, 20899}, {23500, 23599}}
	ports := map[int]bool{}
	for p := 20850; p <= 20855; p++ {
		ports[p] = true
	}
	got := blockSpecs(blocksWithout(blocks, ports, clientRangeMinSize))
	want := []string{"20800-20849", "20856-20899", "23500-23599"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("blocksWithout = %v, ожидалось %v", got, want)
	}

	// Огрызок короче минимального куска клиенту не выдаётся.
	for p := 20800; p <= 20895; p++ {
		ports[p] = true
	}
	got = blockSpecs(blocksWithout(blocks, ports, clientRangeMinSize))
	if strings.Join(got, ",") != "23500-23599" {
		t.Errorf("огрызок 20896-20899 должен отпасть, получено %v", got)
	}
}

func TestDestPortAndRuleArgs(t *testing.T) {
	for dest, want := range map[string]string{
		"172.29.172.2:38418": "38418",
		"[fd00::2]:51820":    "51820",
		"1.2.3.4:100-200":    "100-200",
		"10.0.0.5":           "",
		"fd00::2":            "",
	} {
		if got := destPort(dest); got != want {
			t.Errorf("destPort(%q) = %q, ожидалось %q", dest, got, want)
		}
	}

	args := splitRuleArgs(`-A DOCKER -p tcp -m comment --comment "a -j REDIRECT b" -j DNAT --to-destination 1.2.3.4:80`)
	if len(args) != 12 || args[7] != "a -j REDIRECT b" || args[10] != "--to-destination" {
		t.Errorf("кавычки в комментарии разобраны неверно: %q", args)
	}
}

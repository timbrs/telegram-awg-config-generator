package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Режим «случайный порт»: сервер принимает AWG-трафик на нескольких случайных
// блоках UDP-портов, а каждый новый ключ получает свой порт в Endpoint.
// Один и тот же порт у всех — заметный признак для DPI.
//
// Перехватывается НЕ весь диапазон, а несколько узких блоков, выбранных
// случайно и проверенных на занятость: широкий DNAT увёл бы в туннель трафик
// любого другого UDP-сервиса, который появится на сервере потом.
//
// Механика — DNAT в отдельной цепочке nat/PREROUTING. Правила ставит и снимает
// systemd-юнит: он переживает перезагрузку, работает одинаково для docker и
// native, не трогает чужой awg0.conf и при каждом старте заново узнаёт IP
// контейнера (докер выдаёт его заново).
//
// ВСЕ команды этого файла идут через SSHRun, а не execAWG: правила нужны на
// хосте, а не внутри контейнера.
const (
	randomPortScriptPath = "/usr/local/bin/awg-randomport.sh"
	randomPortUnitPath   = "/etc/systemd/system/awg-randomport.service"
	randomPortUnitName   = "awg-randomport"
	randomPortChain      = "AWGRANDOM"

	// defaultPortRange — пул, из которого нарезаются блоки. Кончается на 32767
	// не случайно: дальше начинается эфемерный диапазон ядра
	// (net.ipv4.ip_local_port_range, по умолчанию 32768-60999). Ответы на
	// исходящие соединения сервера DNAT не заденет — nat-таблица смотрит только
	// на первый пакет соединения, — но сервис, который сам займёт там UDP-порт,
	// оказался бы под перехватом.
	defaultPortRange = "20000-32767"

	// portBlockSize/portBlockCount — сколько портов реально слушает сервер:
	// 8 блоков по 100 = 800 портов. Достаточно, чтобы порт клиента не угадывался,
	// и достаточно мало, чтобы не занимать пул целиком.
	portBlockSize  = 100
	portBlockCount = 8

	minRandomPort = 1024
	maxRandomPort = 65535
	// minRandomPortSpan — в пул должны помещаться все блоки, иначе выбирать не из чего.
	minRandomPortSpan = portBlockSize * portBlockCount
)

// portBlock — непрерывный отрезок UDP-портов, который пробрасывается на AWG.
type portBlock struct {
	Lo int
	Hi int
}

func (b portBlock) String() string { return fmt.Sprintf("%d-%d", b.Lo, b.Hi) }

func (b portBlock) contains(port int) bool { return port >= b.Lo && port <= b.Hi }

// parsePortRange разбирает «20000-32767».
func parsePortRange(s string) (lo, hi int, err error) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("диапазон задаётся как «20000-32767»")
	}
	lo, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("начало диапазона — не число")
	}
	hi, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("конец диапазона — не число")
	}
	if lo < minRandomPort || hi > maxRandomPort {
		return 0, 0, fmt.Errorf("порты должны быть в пределах %d-%d", minRandomPort, maxRandomPort)
	}
	if hi-lo+1 < minRandomPortSpan {
		return 0, 0, fmt.Errorf("в диапазон должно помещаться %d блоков по %d портов (минимум %d портов)",
			portBlockCount, portBlockSize, minRandomPortSpan)
	}
	return lo, hi, nil
}

// parsePortBlocks разбирает список блоков из config.yaml.
func parsePortBlocks(specs []string) []portBlock {
	blocks := make([]portBlock, 0, len(specs))
	for _, spec := range specs {
		lo, hi, err := parseBlockSpec(spec)
		if err != nil {
			continue
		}
		blocks = append(blocks, portBlock{Lo: lo, Hi: hi})
	}
	return blocks
}

func parseBlockSpec(spec string) (lo, hi int, err error) {
	parts := strings.Split(strings.TrimSpace(spec), "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("блок задаётся как «24500-24599»")
	}
	if lo, err = strconv.Atoi(strings.TrimSpace(parts[0])); err != nil {
		return 0, 0, err
	}
	if hi, err = strconv.Atoi(strings.TrimSpace(parts[1])); err != nil {
		return 0, 0, err
	}
	if lo < minRandomPort || hi > maxRandomPort || hi < lo {
		return 0, 0, fmt.Errorf("блок %s вне допустимых портов", spec)
	}
	return lo, hi, nil
}

func blockSpecs(blocks []portBlock) []string {
	specs := make([]string, 0, len(blocks))
	for _, b := range blocks {
		specs = append(specs, b.String())
	}
	return specs
}

// pickPortBlocks нарезает из пула [lo,hi] несколько случайных блоков, в которых
// ни один порт никем не занят.
//
// Блоки не пересекаются между собой и идут по возрастанию — так их проще читать
// в config.yaml и в правилах iptables.
func pickPortBlocks(lo, hi int, busy map[int]bool, count, size int, r *rand.Rand) []portBlock {
	if size < 1 || count < 1 || hi-lo+1 < size {
		return nil
	}

	// Стартовые позиции выравниваем по размеру блока: так блоки гарантированно
	// не наезжают друг на друга, а перебор возможных позиций остаётся дешёвым.
	slots := (hi - lo + 1) / size
	if slots < 1 {
		return nil
	}

	free := func(slot int) (portBlock, bool) {
		b := portBlock{Lo: lo + slot*size, Hi: lo + slot*size + size - 1}
		for p := b.Lo; p <= b.Hi; p++ {
			if busy[p] {
				return portBlock{}, false
			}
		}
		return b, true
	}

	taken := make(map[int]bool)
	var blocks []portBlock

	// Случайные попытки: пул на порядки больше нужного числа блоков, поэтому
	// почти всегда хватает первых же.
	for attempt := 0; attempt < count*20 && len(blocks) < count; attempt++ {
		slot := r.Intn(slots)
		if taken[slot] {
			continue
		}
		b, ok := free(slot)
		if !ok {
			taken[slot] = true // занятый слот больше не проверяем
			continue
		}
		taken[slot] = true
		blocks = append(blocks, b)
	}

	// Страховка на тесный пул: добираем последовательным проходом.
	for slot := 0; slot < slots && len(blocks) < count; slot++ {
		if taken[slot] {
			continue
		}
		if b, ok := free(slot); ok {
			taken[slot] = true
			blocks = append(blocks, b)
		}
	}

	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Lo < blocks[j].Lo })
	return blocks
}

// randomPortParams — всё, что нужно скрипту на сервере.
type randomPortParams struct {
	Blocks    []portBlock
	NetIface  string // пусто — скрипт определит сам по маршруту по умолчанию
	AWGPort   int
	Container string // непусто только для docker-режима
}

// buildRandomPortScript собирает /usr/local/bin/awg-randomport.sh.
//
// Скрипт идемпотентен: цепочка пересоздаётся с нуля при каждом запуске, поэтому
// повторный старт юнита не плодит дубли правил.
func buildRandomPortScript(p randomPortParams) string {
	specs := strings.Join(blockSpecs(p.Blocks), " ")
	return fmt.Sprintf(`#!/bin/sh
# awg-randomport — приём AWG на случайных блоках UDP-портов.
# Файл создан ботом AWGconfBot; правки перетрутся при следующем включении опции.
set -eu

BLOCKS='%s'
NET_IFACE='%s'
AWG_PORT=%d
CONTAINER='%s'
CHAIN=%s

[ -n "$NET_IFACE" ] || NET_IFACE=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
[ -n "$NET_IFACE" ] || { echo "не удалось определить внешний интерфейс" >&2; exit 1; }

if [ "${1:-start}" = "stop" ]; then
	while iptables -t nat -D PREROUTING -i "$NET_IFACE" -p udp -j "$CHAIN" 2>/dev/null; do :; done
	iptables -t nat -F "$CHAIN" 2>/dev/null || true
	iptables -t nat -X "$CHAIN" 2>/dev/null || true
	exit 0
fi

# Для docker цель — адрес контейнера: правило стоит раньше цепочки DOCKER, а
# DNAT терминален, поэтому докеровский проброс порта уже не отработает.
# Пустой IP — контейнер в host-сети: там порт слушается прямо на хосте и нужен
# обычный REDIRECT.
target=''
if [ -n "$CONTAINER" ]; then
	ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$CONTAINER" 2>/dev/null | awk '{print $1}')
	if [ -n "$ip" ]; then
		target="$ip:$AWG_PORT"
	else
		echo "контейнер $CONTAINER без своего IP — перенаправляю на порт хоста" >&2
	fi
fi

iptables -t nat -N "$CHAIN" 2>/dev/null || iptables -t nat -F "$CHAIN"

# Блоки выбирались свободными, но с тех пор на сервере мог появиться новый
# UDP-сервис. Всё, что кто-то слушает (включая сам AWG), пропускаем как есть.
# $4 — локальный адрес: пятое поле это peer, у него порт всегда «*».
for p in $(ss -lunH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un); do
	case "$p" in ''|*[!0-9]*) continue;; esac
	iptables -t nat -A "$CHAIN" -p udp --dport "$p" -j RETURN
done

for block in $BLOCKS; do
	lo=${block%%%%-*}
	hi=${block##*-}
	if [ -n "$target" ]; then
		iptables -t nat -A "$CHAIN" -p udp --dport "$lo:$hi" -j DNAT --to-destination "$target"
	else
		iptables -t nat -A "$CHAIN" -p udp --dport "$lo:$hi" -j REDIRECT --to-ports "$AWG_PORT"
	fi
done

iptables -t nat -C PREROUTING -i "$NET_IFACE" -p udp -j "$CHAIN" 2>/dev/null \
	|| iptables -t nat -I PREROUTING 1 -i "$NET_IFACE" -p udp -j "$CHAIN"
`, specs, p.NetIface, p.AWGPort, p.Container, randomPortChain)
}

// buildRandomPortUnit — systemd-юнит, запускающий скрипт при загрузке.
//
// Type=oneshot + RemainAfterExit: юнит «активен», пока правила стоят, а
// systemctl stop зовёт скрипт с аргументом stop и снимает их.
func buildRandomPortUnit() string {
	return fmt.Sprintf(`[Unit]
Description=AWGconfBot: DNAT random UDP port blocks to AmneziaWG
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s start
ExecStop=%s stop

[Install]
WantedBy=multi-user.target
`, randomPortScriptPath, randomPortScriptPath)
}

// randomPortAWGPort — порт, на котором сервер принимает AWG.
func randomPortAWGPort(srv ServerConfig) (int, error) {
	params, err := ReadServerConfig(srv)
	if err == nil && params.ListenPort != "" {
		if port, convErr := strconv.Atoi(params.ListenPort); convErr == nil {
			return port, nil
		}
	}
	if srv.Port != 0 {
		return srv.Port, nil
	}
	if err != nil {
		return 0, fmt.Errorf("не удалось узнать порт AWG: %w", err)
	}
	return 0, fmt.Errorf("в конфиге сервера нет ListenPort")
}

// EnableRandomPort выбирает свободные блоки, заливает скрипт с юнитом и включает
// их. Возвращает выбранные блоки — их нужно сохранить в config.yaml, иначе бот
// не будет знать, из чего выдавать порты клиентам.
func EnableRandomPort(srv ServerConfig, rangeSpec string, reuse []portBlock) ([]portBlock, error) {
	lo, hi, err := parsePortRange(rangeSpec)
	if err != nil {
		return nil, err
	}
	awgPort, err := randomPortAWGPort(srv)
	if err != nil {
		return nil, err
	}

	busy, err := listeningUDPPorts(srv)
	if err != nil {
		return nil, fmt.Errorf("проверка занятых портов: %w", err)
	}
	// Без этой проверки блок молча ложится под чужой REDIRECT/DNAT (serverD, 15.09.2026),
	// поэтому здесь её сбой — ошибка, а не повод выбрать блоки вслепую.
	captures, err := foreignNATCaptures(srv, awgPort)
	if err != nil {
		return nil, fmt.Errorf("проверка чужих перехватов портов: %w", err)
	}

	blocks := chooseRandomPortBlocks(lo, hi, reuse, busy, capturedPortSet(captures),
		rand.New(rand.NewSource(time.Now().UnixNano())))
	if len(blocks) == 0 {
		return nil, fmt.Errorf("в диапазоне %s не нашлось свободных блоков по %d портов", rangeSpec, portBlockSize)
	}

	container := ""
	if srv.Mode != "native" {
		container = containerName
	}
	script := buildRandomPortScript(randomPortParams{
		Blocks:    blocks,
		NetIface:  srv.NetIface,
		AWGPort:   awgPort,
		Container: container,
	})

	if err := writeHostFile(srv, randomPortScriptPath, script, "755"); err != nil {
		return nil, fmt.Errorf("запись скрипта: %w", err)
	}
	if err := writeHostFile(srv, randomPortUnitPath, buildRandomPortUnit(), "644"); err != nil {
		return nil, fmt.Errorf("запись systemd-юнита: %w", err)
	}

	cmd := fmt.Sprintf("systemctl daemon-reload && systemctl enable %s && systemctl restart %s",
		randomPortUnitName, randomPortUnitName)
	if out, err := SSHRunTimeout(srv, cmd, 30*time.Second); err != nil {
		return nil, fmt.Errorf("запуск %s: %w (%s)", randomPortUnitName, err, strings.TrimSpace(out))
	}
	return blocks, nil
}

// chooseRandomPortBlocks — блоки для режима «случайный порт».
//
// Годные старые блоки сохраняются, недостающие добираются: Endpoint уже выданных
// ключей указывает на порты из старых блоков. Старый блок НЕ выкидывается даже
// тогда, когда его перекрывает чужой перехват, — это отрезало бы живых клиентов;
// о пересечении предупреждает экран «Случайный порт» (RandomPortConflicts).
// Новые же блоки берутся только из портов, которые никто не слушает (busy) и
// никто чужой не перехватывает (foreign).
func chooseRandomPortBlocks(lo, hi int, reuse []portBlock, busy, foreign map[int]bool, r *rand.Rand) []portBlock {
	blocks := usableBlocks(reuse, lo, hi, busy)
	need := portBlockCount - len(blocks)
	if need <= 0 {
		return blocks
	}
	taken := make(map[int]bool, len(busy)+len(foreign)+len(blocks)*portBlockSize)
	for p := range busy {
		taken[p] = true
	}
	for p := range foreign {
		taken[p] = true
	}
	for _, b := range blocks {
		for p := b.Lo; p <= b.Hi; p++ {
			taken[p] = true
		}
	}
	blocks = append(blocks, pickPortBlocks(lo, hi, taken, need, portBlockSize, r)...)
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].Lo < blocks[j].Lo })
	return blocks
}

// usableBlocks оставляет ранее выбранные блоки, если они всё ещё годятся:
// лежат в текущем пуле и никем не заняты. Смысл в том, чтобы переприменение
// режима не отрезало уже выданные ключи — их Endpoint указывает на старый порт.
func usableBlocks(blocks []portBlock, lo, hi int, busy map[int]bool) []portBlock {
	var ok []portBlock
	for _, b := range blocks {
		if b.Lo < lo || b.Hi > hi {
			continue
		}
		free := true
		for p := b.Lo; p <= b.Hi; p++ {
			if busy[p] {
				free = false
				break
			}
		}
		if free {
			ok = append(ok, b)
		}
	}
	return ok
}

// DisableRandomPort снимает правила и выключает юнит. Файлы удаляются: включить
// режим заново — это перезалить их с актуальными параметрами.
func DisableRandomPort(srv ServerConfig) error {
	cmd := fmt.Sprintf(
		"systemctl disable --now %s 2>/dev/null; sh %s stop 2>/dev/null; rm -f %s %s; systemctl daemon-reload; true",
		randomPortUnitName, randomPortScriptPath, randomPortUnitPath, randomPortScriptPath)
	if out, err := SSHRunTimeout(srv, cmd, 30*time.Second); err != nil {
		return fmt.Errorf("выключение %s: %w (%s)", randomPortUnitName, err, strings.TrimSpace(out))
	}
	return nil
}

// RandomPortStatus — состояние режима на сервере: активен ли юнит и стоит ли
// цепочка в nat/PREROUTING. Второе важнее: юнит мог отработать давно, а правила
// кто-то снял руками (или их сбросил другой фаервол).
func RandomPortStatus(srv ServerConfig) (unitActive bool, chainInstalled bool, err error) {
	cmd := fmt.Sprintf(
		"sh -c 'systemctl is-active %s 2>/dev/null; iptables -t nat -S %s 2>/dev/null | grep -q -- \"-j DNAT\\|-j REDIRECT\" && iptables -t nat -S PREROUTING 2>/dev/null | grep -q -- \"-j %s\" && echo CHAIN_OK; true'",
		randomPortUnitName, randomPortChain, randomPortChain)
	out, err := SSHRunTimeout(srv, cmd, 15*time.Second)
	if err != nil {
		return false, false, fmt.Errorf("проверка состояния: %w", err)
	}
	unitActive = strings.Contains(out, "active") && !strings.Contains(out, "inactive")
	chainInstalled = strings.Contains(out, "CHAIN_OK")
	return unitActive, chainInstalled, nil
}

// writeHostFile кладёт файл на ХОСТ (не в контейнер) через base64.
func writeHostFile(srv ServerConfig, path, content, mode string) error {
	cmd := fmt.Sprintf("sh -c 'printf %%s %s | base64 -d > %s && chmod %s %s'",
		base64.StdEncoding.EncodeToString([]byte(content)), path, mode, path)
	if out, err := SSHRunTimeout(srv, cmd, 20*time.Second); err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

// listeningUDPPorts — все UDP-порты, которые на сервере кто-то слушает.
// Ровно их скрипт пропускает мимо DNAT, поэтому ни блок, ни порт клиента на них
// попадать не должны: трафик ушёл бы в чужой сервис.
func listeningUDPPorts(srv ServerConfig) (map[int]bool, error) {
	out, err := SSHRunTimeout(srv, "sh -c 'ss -lunH 2>/dev/null || ss -lun 2>/dev/null'", 15*time.Second)
	if err != nil {
		return nil, err
	}
	return parseListeningUDPPorts(out), nil
}

// parseListeningUDPPorts вытаскивает номера портов из вывода `ss -lun`.
// Формат строки: "UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*" — локальный адрес идёт
// ЧЕТВЁРТЫМ полем (пятое — peer, там порт всегда «*»); у IPv6 это "[::]:51820",
// поэтому берём хвост после последнего двоеточия.
func parseListeningUDPPorts(ssOutput string) map[int]bool {
	busy := make(map[int]bool)
	for _, line := range strings.Split(ssOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := fields[3]
		idx := strings.LastIndex(addr, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(addr[idx+1:])
		if err != nil {
			continue
		}
		busy[port] = true
	}
	return busy
}

// Сколько портов выдаётся одному клиенту. Меньше сотни — набор легко
// перебрать и заблокировать целиком; больше шестисот — правило на роутере и
// строка AWG_REMOTE распухают без пользы.
const (
	clientPortsMin     = 100
	clientPortsMax     = 600
	clientRangeMinSize = 8
)

// pickClientPortRanges нарезает клиенту его собственный набор портов: по
// кусочку в КАЖДОМ блоке сервера. Разброс по всем блокам — это и есть смысл:
// одно заблокированное правило DPI отнимает у клиента лишь один кусок.
//
// Наборы разных клиентов пересекаются, и это нормально: занятость не
// отслеживается, порт в блоке всё равно ведёт на один и тот же AWG.
//
// При большом числе блоков нижняя граница куска (8 портов) может вытянуть
// сумму выше цели — 32 блока дадут 256 портов даже при цели 100. Это дешевле,
// чем оставить клиенту по два-три порта на блок.
func pickClientPortRanges(blocks []portBlock, r *rand.Rand) []portBlock {
	if len(blocks) == 0 {
		return nil
	}
	target := clientPortsMin + r.Intn(clientPortsMax-clientPortsMin+1)
	per := (target + len(blocks)/2) / len(blocks)
	if per < clientRangeMinSize {
		per = clientRangeMinSize
	}

	out := make([]portBlock, 0, len(blocks))
	for _, b := range blocks {
		size := b.Hi - b.Lo + 1
		take := per
		if take > size {
			take = size
		}
		lo := b.Lo + r.Intn(size-take+1)
		out = append(out, portBlock{Lo: lo, Hi: lo + take - 1})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lo < out[j].Lo })
	return out
}

// pickClientPortSet — набор портов нового ключа и порт для его Endpoint.
//
// Куски блоков, которые перехватывает чужое NAT-правило, клиенту не выдаются
// вовсе: пакет туда уйдёт в другой сервис, и ключ не подключится ни разу (serverD,
// 15.09.2026). awgPort — порт AWG на сервере: перехват на него самого не чужой.
//
// Endpoint выбирается из этого же набора и с проверкой занятости: набор режется
// вслепую, а вот единственный порт, который увидит клиент без awg-proxy, на
// живой сервис попасть не должен. При недоступном `ss` или сорвавшемся снятии
// правил NAT порт всё равно выдаётся — потерять ключ из-за одной сорвавшейся
// команды хуже, чем рискнуть одним портом; конфликт виден на экране «Случайный порт».
func pickClientPortSet(srv ServerConfig, awgPort int, r *rand.Rand) (ranges []portBlock, endpoint int, err error) {
	blocks := parsePortBlocks(srv.RandomPortBlocks)
	if len(blocks) == 0 {
		return nil, 0, fmt.Errorf("для сервера не выбрано ни одного блока портов")
	}

	var foreign map[int]bool
	if awgPort > 0 {
		if captures, capErr := foreignNATCaptures(srv, awgPort); capErr == nil {
			foreign = capturedPortSet(captures)
		}
	}
	if len(foreign) > 0 {
		blocks = blocksWithout(blocks, foreign, clientRangeMinSize)
		if len(blocks) == 0 {
			return nil, 0, fmt.Errorf("все блоки портов перекрыты чужими правилами NAT")
		}
	}
	ranges = pickClientPortRanges(blocks, r)

	busy, busyErr := listeningUDPPorts(srv)
	if busyErr != nil || busy == nil {
		busy = make(map[int]bool)
	}
	for p := range foreign {
		busy[p] = true
	}
	endpoint = randomPortFromBlocks(ranges, busy, r)
	if endpoint == 0 {
		return nil, 0, fmt.Errorf("в наборе портов клиента не осталось свободных")
	}
	return ranges, endpoint, nil
}

// clientPortsSpec — набор в том виде, в каком его понимает awg-proxy:
// «20150-20179,21500-21529».
func clientPortsSpec(ranges []portBlock) string {
	return strings.Join(blockSpecs(ranges), ",")
}

// randomPortFromBlocks — случайный незанятый порт из блоков; 0, если свободных нет.
func randomPortFromBlocks(blocks []portBlock, busy map[int]bool, r *rand.Rand) int {
	total := 0
	for _, b := range blocks {
		total += b.Hi - b.Lo + 1
	}
	if total <= 0 {
		return 0
	}

	pick := func(n int) int {
		for _, b := range blocks {
			size := b.Hi - b.Lo + 1
			if n < size {
				return b.Lo + n
			}
			n -= size
		}
		return 0
	}

	for i := 0; i < 30; i++ {
		if port := pick(r.Intn(total)); port != 0 && !busy[port] {
			return port
		}
	}
	for _, b := range blocks {
		for port := b.Lo; port <= b.Hi; port++ {
			if !busy[port] {
				return port
			}
		}
	}
	return 0
}

// --- Чужие перехваты портов ---------------------------------------------------
//
// «Свободен» раньше значило только «никто не слушает» (ss -lun). Этого мало: порт
// может перехватывать чужое правило nat — REDIRECT или DNAT в другой сервис, у
// которого на этом порту нет сокета. 15.09.2026 на serverD (moscow-hop-3) так и
// вышло: REDIRECT 20000-20999 -> :51821 соседнего AWG стоял выше цепочки бота,
// блок 20800-20899 целиком уходил в чужой сервер, и 8 выданных ключей не
// подключились ни разу. Ни один счётчик об этом не сообщал.
//
// Чужим считается правило, уводящее пакет НЕ на порт нашего AWG. Перехват на сам
// AWG (например, широкий DNAT всего диапазона в тот же контейнер) не конфликт.
// Разбираются iptables (legacy и nft-обёртка) — с переходами между цепочками и
// RETURN — и «чистые» правила nft, построчно. Условия правил (-s, -i …) не
// учитываются: лучше лишний раз обойти порт, чем выдать ключ в чужой сервис.

// natCapture — UDP-порты, которые чужое NAT-правило уводит в другой сервис.
type natCapture struct {
	Ports  []portBlock
	Target string // куда уводит: «REDIRECT :51821», «DNAT 10.0.0.5:9999»
}

const natDumpMarker = "@@AWGCONFBOT-NFT@@"

// foreignNATCaptures снимает правила nat с сервера и возвращает чужие перехваты.
func foreignNATCaptures(srv ServerConfig, awgPort int) ([]natCapture, error) {
	cmd := "sh -c '(iptables-save -t nat; ip6tables-save -t nat) 2>/dev/null; echo " + natDumpMarker +
		"; nft list ruleset 2>/dev/null | grep -E \"dnat|redirect\" | grep \"udp dport\"; true'"
	out, err := SSHRunTimeout(srv, cmd, 20*time.Second)
	if err != nil {
		return nil, err
	}
	ipt, nft, _ := strings.Cut(out, natDumpMarker)
	ours := serverAddrs(srv)
	return append(parseIptablesNATCaptures(ipt, awgPort, ours), parseNftNATCaptures(nft, awgPort, ours)...), nil
}

// serverAddrs — адреса, на которые приходят клиенты сервера. Правила NAT про другие
// адреса их пакеты не трогают: на serverC в ip6tables десятки DNAT 1:1 для чужих /128
// (NAT66 роутеров) без всякого порта — без этой отсечки весь пул выглядел бы занятым.
func serverAddrs(srv ServerConfig) []netip.Addr {
	var out []netip.Addr
	for _, s := range []string{srv.IP, srv.EndpointIP, srv.IPv6Host} {
		s = strings.Trim(strings.TrimSpace(s), "[]")
		if i := strings.Index(s, "/"); i >= 0 {
			s = s[:i]
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// dstMatches — касается ли условие -d / daddr адресов сервера. Адреса неизвестны или
// условие не разобрать — считаем, что касается: лучше лишний раз обойти порт.
func dstMatches(spec string, neg bool, ours []netip.Addr) bool {
	if len(ours) == 0 {
		return true
	}
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		a, aerr := netip.ParseAddr(spec)
		if aerr != nil {
			return true
		}
		prefix = netip.PrefixFrom(a, a.BitLen())
	}
	hit := false
	for _, a := range ours {
		if prefix.Contains(a) {
			hit = true
			break
		}
	}
	return hit != neg
}

// RandomPortConflicts — какие блоки сервера перекрыты чужими перехватами (для экрана
// «Случайный порт»). Пусто — пересечений нет.
func RandomPortConflicts(srv ServerConfig) ([]string, error) {
	blocks := parsePortBlocks(srv.RandomPortBlocks)
	if len(blocks) == 0 {
		return nil, nil
	}
	awgPort, err := randomPortAWGPort(srv)
	if err != nil {
		return nil, err
	}
	captures, err := foreignNATCaptures(srv, awgPort)
	if err != nil {
		return nil, err
	}
	return blockConflicts(blocks, captures), nil
}

// blockConflicts описывает пересечения блоков с чужими перехватами.
func blockConflicts(blocks []portBlock, captures []natCapture) []string {
	var out []string
	seen := make(map[string]bool) // одно правило обычно стоит и в iptables, и в ip6tables
	for _, b := range blocks {
		for _, c := range captures {
			overlap := intersectPortBlocks([]portBlock{b}, c.Ports)
			if len(overlap) == 0 {
				continue
			}
			line := fmt.Sprintf("блок %s: порты %s уходят в %s", b, portBlocksSpec(overlap), c.Target)
			if !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
		}
	}
	return out
}

// capturedPortSet — все порты перехватов одним множеством.
func capturedPortSet(captures []natCapture) map[int]bool {
	set := make(map[int]bool)
	for _, c := range captures {
		for _, b := range c.Ports {
			for p := b.Lo; p <= b.Hi; p++ {
				set[p] = true
			}
		}
	}
	return set
}

// blocksWithout режет блоки вокруг помеченных портов; куски короче minSize отбрасываются.
func blocksWithout(blocks []portBlock, ports map[int]bool, minSize int) []portBlock {
	var out []portBlock
	for _, b := range blocks {
		start := -1
		for p := b.Lo; p <= b.Hi+1; p++ {
			free := p <= b.Hi && !ports[p]
			switch {
			case free && start < 0:
				start = p
			case !free && start >= 0:
				if p-start >= minSize {
					out = append(out, portBlock{Lo: start, Hi: p - 1})
				}
				start = -1
			}
		}
	}
	return out
}

// Множества портов: nil — «порт не ограничен», пустой срез — «ни одного порта».
var allPorts = []portBlock{{Lo: 1, Hi: maxRandomPort}}

func intersectPortBlocks(a, b []portBlock) []portBlock {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := []portBlock{}
	for _, x := range a {
		for _, y := range b {
			lo, hi := max(x.Lo, y.Lo), min(x.Hi, y.Hi)
			if lo <= hi {
				out = append(out, portBlock{Lo: lo, Hi: hi})
			}
		}
	}
	return out
}

func subtractPortBlocks(a, holes []portBlock) []portBlock {
	if len(holes) == 0 {
		return a
	}
	if a == nil {
		a = allPorts
	}
	out := []portBlock{}
	for _, x := range a {
		cur := []portBlock{x}
		for _, h := range holes {
			var next []portBlock
			for _, c := range cur {
				if h.Hi < c.Lo || h.Lo > c.Hi {
					next = append(next, c)
					continue
				}
				if c.Lo < h.Lo {
					next = append(next, portBlock{Lo: c.Lo, Hi: h.Lo - 1})
				}
				if h.Hi < c.Hi {
					next = append(next, portBlock{Lo: h.Hi + 1, Hi: c.Hi})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return out
}

func portBlocksSpec(blocks []portBlock) string {
	parts := make([]string, 0, len(blocks))
	for _, b := range blocks {
		if b.Lo == b.Hi {
			parts = append(parts, strconv.Itoa(b.Lo))
		} else {
			parts = append(parts, b.String())
		}
	}
	return strings.Join(parts, ",")
}

// iptRule — то из правила iptables, что влияет на перехват UDP-портов.
type iptRule struct {
	proto    string
	negProto bool
	dports   []portBlock // nil — порт не ограничен
	negDport bool
	cond     bool   // есть прочие условия (-i, -s, -d, -m …): такой RETURN не безусловен
	dst      string // -d: правило касается только пакетов на этот адрес
	negDst   bool
	target   string
	toPorts  string
	toDest   string
}

// parseIptablesNATCaptures разбирает вывод iptables-save (v4 и v6 — отдельными
// таблицами) и проходит nat/PREROUTING так, как его проходит ядро.
func parseIptablesNATCaptures(save string, awgPort int, ours []netip.Addr) []natCapture {
	var out []natCapture
	var chains map[string][]iptRule
	flush := func() {
		if chains != nil {
			walkNATChain(chains, "PREROUTING", nil, awgPort, ours, 0, &out)
		}
		chains = nil
	}
	for _, line := range strings.Split(save, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "*"):
			flush()
			if line == "*nat" {
				chains = make(map[string][]iptRule)
			}
		case line == "COMMIT":
			flush()
		case chains != nil && strings.HasPrefix(line, "-A "):
			args := splitRuleArgs(line)
			if len(args) >= 2 {
				if r, ok := parseIptRule(args[2:]); ok {
					chains[args[1]] = append(chains[args[1]], r)
				}
			}
		}
	}
	flush()
	return out
}

func parseIptRule(args []string) (iptRule, bool) {
	var r iptRule
	neg := false
	for i := 0; i < len(args); i++ {
		a, next := args[i], ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		if a == "!" {
			neg = true
			continue
		}
		switch a {
		case "-p", "--protocol":
			r.proto, r.negProto = strings.ToLower(next), neg
			i++
		case "--dport", "--destination-port", "--dports", "--destination-ports":
			ports, ok := parsePortList(next, ":")
			if !ok {
				return r, false
			}
			r.dports, r.negDport = ports, neg
			i++
		case "-j", "--jump", "-g", "--goto":
			r.target = next
			i++
		case "--to-ports":
			r.toPorts = next
			i++
		case "--to-destination":
			r.toDest = next
			i++
		case "-m", "--match":
			if next != "udp" && next != "tcp" && next != "multiport" && next != "comment" && next != "addrtype" {
				r.cond = true
			}
			i++
		case "--comment", "--dst-type":
			i++
		case "-d", "--destination":
			r.dst, r.negDst, r.cond = next, neg, true
			i++
		case "-i", "--in-interface", "-s", "--source":
			r.cond = true
			i++
		default:
			if strings.HasPrefix(a, "-") {
				r.cond = true
			}
		}
		neg = false
	}
	return r, true
}

func walkNATChain(chains map[string][]iptRule, chain string, entry []portBlock, awgPort int, ours []netip.Addr, depth int, out *[]natCapture) {
	if depth > 8 {
		return
	}
	var returned []portBlock
	for _, r := range chains[chain] {
		if r.negProto || r.negDport || (r.proto != "" && r.proto != "udp" && r.proto != "17" && r.proto != "all") {
			continue
		}
		if r.dst != "" && !dstMatches(r.dst, r.negDst, ours) {
			continue // правило про чужой адрес (например, NAT66 1:1 для /128 роутера)
		}
		eff := subtractPortBlocks(intersectPortBlocks(entry, r.dports), returned)
		if eff != nil && len(eff) == 0 {
			continue
		}
		switch r.target {
		case randomPortChain:
			// своя цепочка
		case "RETURN":
			if r.cond {
				continue // условный RETURN (например, -i docker0) пакет с WAN не вернёт
			}
			if r.dports == nil {
				return // безусловный RETURN: дальше по цепочке не пойдёт ни один пакет
			}
			returned = append(returned, eff...)
		case "DNAT", "REDIRECT":
			port := r.toPorts
			if r.target == "DNAT" {
				port = destPort(r.toDest)
			}
			if p, _ := strconv.Atoi(strings.SplitN(port, "-", 2)[0]); p == awgPort {
				continue
			}
			if eff == nil {
				eff = allPorts
			}
			target := "REDIRECT :" + port
			if r.target == "DNAT" {
				target = "DNAT " + r.toDest
			}
			*out = append(*out, natCapture{Ports: eff, Target: target})
		default:
			if _, ok := chains[r.target]; ok {
				walkNATChain(chains, r.target, eff, awgPort, ours, depth+1, out)
			}
		}
	}
}

// destPort — порт из «1.2.3.4:51820», «[fd00::2]:51820», «1.2.3.4:100-200»; "" — без порта.
func destPort(dest string) string {
	if strings.HasPrefix(dest, "[") {
		if i := strings.Index(dest, "]:"); i >= 0 {
			return dest[i+2:]
		}
		return ""
	}
	if strings.Count(dest, ":") == 1 {
		return dest[strings.Index(dest, ":")+1:]
	}
	return ""
}

// parsePortList — «53», «20000:20999», «53,5000:5010» (sep — разделитель диапазона).
func parsePortList(spec, sep string) ([]portBlock, bool) {
	var out []portBlock
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loS, hiS, isRange := strings.Cut(part, sep)
		lo, err := strconv.Atoi(strings.TrimSpace(loS))
		if err != nil {
			return nil, false
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(strings.TrimSpace(hiS)); err != nil {
				return nil, false
			}
		}
		out = append(out, portBlock{Lo: lo, Hi: hi})
	}
	return out, len(out) > 0
}

// splitRuleArgs режет строку iptables-save на аргументы с учётом кавычек (комментарии).
func splitRuleArgs(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote, have := false, false
	for _, ch := range line {
		switch {
		case ch == '"':
			inQuote, have = !inQuote, true
		case ch == ' ' && !inQuote:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(ch)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}

var (
	nftDportRe  = regexp.MustCompile(`udp dport (\{[^}]*\}|[0-9][0-9-]*)`)
	nftTargetRe = regexp.MustCompile(`\b(?:redirect to :([0-9]+)|dnat (?:ip6? )?to (\S+))`)
	nftDaddrRe  = regexp.MustCompile(`\bip6? daddr (!= )?(\S+)`)
)

// parseNftNATCaptures — построчно правила nft вида
// «udp dport 20000-20999 … redirect to :51821» / «udp dport { 53, 5000-5010 } dnat ip to 10.0.0.5:9999».
func parseNftNATCaptures(text string, awgPort int, ours []netip.Addr) []natCapture {
	var out []natCapture
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "udp dport !=") {
			continue
		}
		if dd := nftDaddrRe.FindStringSubmatch(line); dd != nil && !dstMatches(dd[2], dd[1] != "", ours) {
			continue
		}
		dm, tm := nftDportRe.FindStringSubmatch(line), nftTargetRe.FindStringSubmatch(line)
		if dm == nil || tm == nil {
			continue
		}
		ports, ok := parsePortList(strings.Trim(dm[1], "{} "), "-")
		if !ok {
			continue
		}
		port, target := tm[1], "REDIRECT :"+tm[1]
		if port == "" {
			port, target = destPort(tm[2]), "DNAT "+tm[2]
		}
		if p, _ := strconv.Atoi(strings.SplitN(port, "-", 2)[0]); p == awgPort {
			continue
		}
		out = append(out, natCapture{Ports: ports, Target: target})
	}
	return out
}

package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
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

	// Годные старые блоки сохраняем, недостающие добираем: Endpoint уже выданных
	// ключей указывает на порты из старых блоков.
	blocks := usableBlocks(reuse, lo, hi, busy)
	if need := portBlockCount - len(blocks); need > 0 {
		taken := make(map[int]bool, len(busy)+len(blocks)*portBlockSize)
		for p := range busy {
			taken[p] = true
		}
		for _, b := range blocks {
			for p := b.Lo; p <= b.Hi; p++ {
				taken[p] = true
			}
		}
		fresh := pickPortBlocks(lo, hi, taken, need, portBlockSize, rand.New(rand.NewSource(time.Now().UnixNano())))
		blocks = append(blocks, fresh...)
		sort.Slice(blocks, func(i, j int) bool { return blocks[i].Lo < blocks[j].Lo })
	}
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

// pickClientPort выбирает порт для нового ключа: случайный из блоков сервера,
// минус занятые. При недоступном `ss` порт всё равно выдаётся — потерять ключ
// из-за одной сорвавшейся команды хуже, чем рискнуть одним портом из сотен.
func pickClientPort(srv ServerConfig) (int, error) {
	blocks := parsePortBlocks(srv.RandomPortBlocks)
	if len(blocks) == 0 {
		return 0, fmt.Errorf("для сервера не выбрано ни одного блока портов")
	}

	busy, err := listeningUDPPorts(srv)
	if err != nil {
		busy = nil
	}
	port := randomPortFromBlocks(blocks, busy, rand.New(rand.NewSource(time.Now().UnixNano())))
	if port == 0 {
		return 0, fmt.Errorf("в блоках сервера не осталось свободных портов")
	}
	return port, nil
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

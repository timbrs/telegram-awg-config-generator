package main

import (
	"net"
	"strconv"
	"strings"
)

// Расчёт MTU для клиентского конфига.
//
// awg-quick, когда MTU не задан, берёт MTU маршрута до endpoint'а минус 80
// (IP + UDP + заголовок WireGuard) и получает привычные 1420. Про AmneziaWG он
// при этом не знает ничего: параметр S4 дописывает свой мусорный префикс к
// КАЖДОМУ пакету данных, и внешняя датаграмма оказывается на S4 байт длиннее
// расчётной. Как только сумма переваливает за 1500, каждый пакет туннеля уходит
// двумя IP-фрагментами. Это не «немного медленнее»: вдвое больше пакетов на
// каждом узле, а потеря любого из двух фрагментов убивает весь пакет, поэтому
// TCP через такой туннель проседает в разы при живом handshake.
//
// Второе, чего awg-quick не видит, — что сервер может заворачивать клиентский
// трафик дальше, в ещё один туннель (HOP). Тогда потолок задаёт уже MTU того
// туннеля, а не 1500 на eth0.
const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	udpHeaderLen  = 8
	// 4 байта типа + 4 индекса получателя + 8 счётчика + 16 тега Poly1305.
	wgTransportOverhead = 32

	// Ethernet без туннелей и PPPoE.
	defaultPathMTU = 1500
	// 1280 — минимальный MTU IPv6: ниже клиент рискует потерять IPv6 вообще.
	minClientMTU = 1280
	// Выше классического значения wg-quick не поднимаемся, даже когда влезает:
	// запас в 80 байт покрывает PPPoE (1492) и мобильные сети у клиента.
	maxClientMTU = 1420
)

// awgPadS4 возвращает размер мусорного префикса, который сервер добавляет к
// каждому пакету данных. Значение может быть диапазоном («12-40») — тогда
// считаем по верхней границе: MTU обязан подходить худшему случаю.
func awgPadS4(params *ServerParams) int {
	if params == nil {
		return 0
	}
	raw := strings.TrimSpace(params.AWGParams["S4"])
	if raw == "" {
		return 0
	}
	worst := 0
	for _, part := range strings.Split(raw, "-") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 0 {
			continue
		}
		if n > worst {
			worst = n
		}
	}
	return worst
}

// ClientMTU считает MTU, который надо записать клиенту.
//
// endpointIsIPv6 — по какому протоколу клиент придёт на сервер: у IPv6 внешний
// заголовок на 20 байт длиннее, и при пограничном S4 разница решает.
// hopMTU — MTU туннеля, в который сервер заворачивает клиентский трафик
// дальше; 0, если трафик уходит прямо в интернет.
func ClientMTU(params *ServerParams, endpointIsIPv6 bool, hopMTU int) int {
	ipHdr := ipv4HeaderLen
	if endpointIsIPv6 {
		ipHdr = ipv6HeaderLen
	}
	mtu := defaultPathMTU - ipHdr - udpHeaderLen - wgTransportOverhead - awgPadS4(params)
	// Пакет клиента должен не только влезть в свою обёртку, но и пройти
	// следующий туннель целиком: фрагментировать его будет уже сервер.
	if hopMTU > 0 && hopMTU < mtu {
		mtu = hopMTU
	}
	if mtu > maxClientMTU {
		mtu = maxClientMTU
	}
	if mtu < minClientMTU {
		mtu = minClientMTU
	}
	return mtu
}

// endpointIsIPv6 определяет семейство адреса, который уедет в Endpoint
// клиентского конфига. Имя хоста (не литерал) считаем IPv4: клиент почти всегда
// приходит по A-записи, а ошибиться в большую сторону дешевле, чем в меньшую.
func endpointIsIPv6(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.To4() == nil
}

// hopProbe ищет туннель, в который сервер заворачивает клиентский трафик.
//
// Признак HOP'а — policy-routing: отдельная таблица маршрутизации, куда
// клиентская подсеть попадает по fwmark, с default'ом в туннельный интерфейс.
// Физические интерфейсы отбрасываем: default через eth0 означает обычный выход
// в интернет, никакой дополнительной обёртки там нет.
const hopProbe = `for t in $(ip rule show | sed -n 's/.*lookup \([^ ]*\)$/\1/p' | grep -vE '^(local|main|default)$' | sort -u); do ip -o route show table "$t" 2>/dev/null; done | awk '$1=="default"{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | sort -u | while read -r i; do case "$i" in eth*|ens*|enp*|eno*|wlan*|br*|bond*) ;; *) echo "$i $(cat /sys/class/net/$i/mtu 2>/dev/null)";; esac; done`

// DetectHopMTU возвращает MTU HOP-туннеля сервера или 0, если такого нет.
// Ошибку не возвращает намеренно: не сумели определить — считаем, что HOP'а
// нет, и MTU выбирается по одной лишь обёртке. Это ровно то поведение, что
// было до появления функции.
func DetectHopMTU(srv ServerConfig) int {
	out, err := SSHRun(srv, hopProbe)
	if err != nil {
		return 0
	}
	best := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		mtu, err := strconv.Atoi(f[1])
		if err != nil || mtu <= 0 {
			continue
		}
		if best == 0 || mtu < best {
			best = mtu
		}
	}
	return best
}

// clientMTUString — значение для поля "mtu" в JSON приложения AmneziaVPN.
// Историческое 1376 остаётся фолбэком: конфиг может собираться из параметров,
// прочитанных без SSH, и там MTU посчитать не из чего.
func clientMTUString(params *ServerParams) string {
	if params != nil && params.ClientMTU > 0 {
		return strconv.Itoa(params.ClientMTU)
	}
	return "1376"
}

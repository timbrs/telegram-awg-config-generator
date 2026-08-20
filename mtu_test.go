package main

import "testing"

func paramsWithS4(s4 string) *ServerParams {
	p := &ServerParams{AWGParams: map[string]string{}}
	if s4 != "" {
		p.AWGParams["S4"] = s4
	}
	return p
}

func TestClientMTU(t *testing.T) {
	cases := []struct {
		name   string
		s4     string
		isV6   bool
		hopMTU int
		want   int
	}{
		// 1500 - 20 - 8 - 32 = 1440, но выше 1420 не поднимаемся.
		{"без S4, IPv4", "", false, 0, 1420},
		// 1500 - 40 - 8 - 32 = 1420 — ровно потолок.
		{"без S4, IPv6", "", true, 0, 1420},
		// Штатный мелкий паддинг: 1440 - 12 = 1428 -> потолок 1420.
		{"S4=12, IPv4", "12", false, 0, 1420},
		// IPv6 съедает ещё 20 байт: 1420 - 12 = 1408, потолок уже не мешает.
		{"S4=12, IPv6", "12", true, 0, 1408},
		// Ровно тот случай, на котором пакеты и начинали фрагментироваться: 1440 - 148 = 1292.
		{"S4=148, IPv4", "148", false, 0, 1292},
		{"S4=148, IPv6", "148", true, 0, 1280}, // 1420-148=1272 — ниже минимума, поднимаем до 1280
		// HOP-туннель режет сильнее собственной обёртки.
		{"HOP 1400 важнее", "12", false, 1400, 1400},
		// ...но не поднимает MTU, если обёртка требует меньше.
		{"HOP 1400 не поднимает", "148", false, 1400, 1292},
		// Диапазон S4 считаем по худшей границе.
		{"S4 диапазоном", "10-200", false, 0, 1280}, // 1440-200=1240 — ниже минимума
		// Мусор в параметре не должен ломать расчёт.
		{"S4 нечисловой", "abc", false, 0, 1420},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClientMTU(paramsWithS4(c.s4), c.isV6, c.hopMTU)
			want := c.want
			if want < minClientMTU {
				want = minClientMTU
			}
			if got != want {
				t.Errorf("ClientMTU(S4=%q, v6=%v, hop=%d) = %d, ожидалось %d",
					c.s4, c.isV6, c.hopMTU, got, want)
			}
		})
	}
}

// Главное свойство: внешний пакет обязан влезть в 1500 байт, иначе каждый
// пакет данных уедет двумя IP-фрагментами.
func TestClientMTUFitsWithoutFragmentation(t *testing.T) {
	for _, s4 := range []string{"", "0", "4", "12", "18", "24", "93", "148", "200"} {
		for _, v6 := range []bool{false, true} {
			mtu := ClientMTU(paramsWithS4(s4), v6, 0)
			ipHdr := ipv4HeaderLen
			if v6 {
				ipHdr = ipv6HeaderLen
			}
			outer := mtu + awgPadS4(paramsWithS4(s4)) + wgTransportOverhead + udpHeaderLen + ipHdr
			// minClientMTU — жёсткий пол: при огромном S4 влезть уже нельзя, и
			// тогда честнее отдать рабочий IPv6-минимум, чем нерабочий конфиг.
			if outer > defaultPathMTU && mtu > minClientMTU {
				t.Errorf("S4=%q v6=%v: MTU %d даёт внешний пакет %d > %d",
					s4, v6, mtu, outer, defaultPathMTU)
			}
		}
	}
}

func TestEndpointIsIPv6(t *testing.T) {
	cases := map[string]bool{
		"1.2.3.4":         false,
		"2a01:db8::1":     true,
		"[2a01:db8::1]":   true,
		"vpn.example.com": false,
		"":                false,
		"::ffff:1.2.3.4":  false, // v4-mapped — обёртка всё равно IPv4-размера
	}
	for host, want := range cases {
		if got := endpointIsIPv6(host); got != want {
			t.Errorf("endpointIsIPv6(%q) = %v, ожидалось %v", host, got, want)
		}
	}
}

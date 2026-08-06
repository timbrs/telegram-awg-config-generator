package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// AWGVersion — версия протокола AmneziaWG.
//
// Значение 15 у ветки 1.5 не опечатка: эта ветка (J1-J3, Itime, I1-I5 отдельными
// полями) прожила два дня в июле 2025 и была откачена — amneziawg-tools
// v1.0.20250706, «Reverted AWG 1.5 changes». Она стоит особняком, а не между 1.0
// и 2.0, поэтому прямые сравнения `<`/`>` для неё бессмысленны: набор параметров
// версии проверяйте через versionHasParam, а хронологию — через versionRank.
type AWGVersion int

const (
	AWGVersionUnknown AWGVersion = 0
	AWGVersion1       AWGVersion = 1  // Jc/Jmin/Jmax, S1-S2, H1-H4 скалярами
	AWGVersion15      AWGVersion = 15 // тупиковая ветка июля 2025: I1-I5, J1-J3, Itime
	AWGVersion2       AWGVersion = 2  // S3/S4, H1-H4 диапазонами, I1-I5 в виде CPS-тегов
	AWGVersion3       AWGVersion = 3  // HeaderProtectionKey, ContentPaddingAddition, тайминги
)

// String — человекочитаемое имя версии для UI.
func (v AWGVersion) String() string {
	switch v {
	case AWGVersionUnknown:
		return "AWG ?"
	case AWGVersion15:
		return "AWG 1.5"
	default:
		return fmt.Sprintf("AWG %d.0", int(v))
	}
}

// versionRank — порядок версий по времени выпуска (1.0 → 1.5 → 2.0 → 3.0 → …).
// Нужен потому, что числовое значение AWGVersion15 выбивается из хронологии.
func versionRank(v AWGVersion) int {
	switch v {
	case AWGVersionUnknown:
		return 0
	case AWGVersion1:
		return 1
	case AWGVersion15:
		return 2
	case AWGVersion2:
		return 3
	default:
		return int(v) + 1 // 3.0 → 4, будущие мажорные версии — по возрастанию
	}
}

// minAWGVersion возвращает более раннюю из двух версий.
func minAWGVersion(a, b AWGVersion) AWGVersion {
	if versionRank(a) <= versionRank(b) {
		return a
	}
	return b
}

// awgParamSpec — описание obfuscation-параметра AmneziaWG.
type awgParamSpec struct {
	Key    string
	MinVer AWGVersion // с какой версии протокола параметр существует
	Server bool       // писать в серверный awg0.conf при установке
}

// awgParamSpecs — единственный источник правды о параметрах обфускации.
// Порядок элементов задаёт порядок строк в генерируемых конфигах.
// Имена сверены с парсером amneziawg-tools (src/config.c).
var awgParamSpecs = []awgParamSpec{
	{"Jc", AWGVersion1, true}, {"Jmin", AWGVersion1, true}, {"Jmax", AWGVersion1, true},
	{"S1", AWGVersion1, true}, {"S2", AWGVersion1, true},
	{"S3", AWGVersion2, true}, {"S4", AWGVersion2, true},
	{"H1", AWGVersion1, true}, {"H2", AWGVersion1, true},
	{"H3", AWGVersion1, true}, {"H4", AWGVersion1, true},
	{"I1", AWGVersion2, false}, {"I2", AWGVersion2, false}, {"I3", AWGVersion2, false},
	{"I4", AWGVersion2, false}, {"I5", AWGVersion2, false},
	{"J1", AWGVersion15, false}, {"J2", AWGVersion15, false}, {"J3", AWGVersion15, false},
	{"Itime", AWGVersion15, false},
	{"HeaderProtectionKey", AWGVersion3, true},
	{"ContentPaddingAddition", AWGVersion3, true},
	{"RekeyAfterTime", AWGVersion3, true}, {"RekeyTimeout", AWGVersion3, true},
	{"RejectAfterTime", AWGVersion3, true}, {"KeepaliveTimeout", AWGVersion3, true},
	{"MaxHandshakeAttempts", AWGVersion3, true},
}

// awgParamMinVer — индекс awgParamSpecs по имени ключа.
var awgParamMinVer = func() map[string]AWGVersion {
	m := make(map[string]AWGVersion, len(awgParamSpecs))
	for _, spec := range awgParamSpecs {
		m[spec.Key] = spec.MinVer
	}
	return m
}()

// reservedInterfaceKeys — ключи [Interface], которые обрабатывает сам awg-quick
// или ядро. Всё остальное в секции считается параметром обфускации AmneziaWG
// и зеркалится в клиентский конфиг как есть — так поддержка новых версий
// протокола не требует правок кода.
var reservedInterfaceKeys = map[string]bool{
	"PrivateKey": true, "ListenPort": true, "FwMark": true,
	"Address": true, "DNS": true, "MTU": true, "Table": true,
	"PreUp": true, "PostUp": true, "PreDown": true, "PostDown": true,
	"SaveConfig": true,
}

// versionHasParam сообщает, существует ли в версии v параметр, появившийся в minVer.
// Ветка 1.5 обрабатывается отдельно: её параметров нет ни в 1.0, ни в 2.0+,
// а параметров 2.0+ нет в ней.
func versionHasParam(v, minVer AWGVersion) bool {
	if v == AWGVersion15 {
		return minVer == AWGVersion1 || minVer == AWGVersion15
	}
	if minVer == AWGVersion15 {
		return false
	}
	return minVer <= v
}

// rangeValueRe — значение вида "100-200" (диапазон H-параметров в AWG 2.0).
var rangeValueRe = regexp.MustCompile(`^\d+-\d+$`)

// deriveConfigVersion определяет версию протокола по набору параметров в конфиге.
// Используется как фолбэк, когда `awg --version` на сервере недоступен.
func deriveConfigVersion(params *ServerParams) AWGVersion {
	if params == nil || len(params.AWGParams) == 0 {
		return AWGVersionUnknown
	}

	for key := range params.AWGParams {
		if awgParamMinVer[key] == AWGVersion3 {
			return AWGVersion3
		}
	}

	if _, ok := params.AWGParams["S3"]; ok {
		return AWGVersion2
	}
	if _, ok := params.AWGParams["S4"]; ok {
		return AWGVersion2
	}
	for _, key := range []string{"H1", "H2", "H3", "H4"} {
		if rangeValueRe.MatchString(params.AWGParams[key]) {
			return AWGVersion2
		}
	}

	if _, ok := params.AWGParams["J1"]; ok {
		return AWGVersion15
	}
	if _, ok := params.AWGParams["Itime"]; ok {
		return AWGVersion15
	}

	if _, ok := params.AWGParams["S1"]; ok {
		return AWGVersion1
	}
	return AWGVersionUnknown
}

// clientParamOrder — порядок параметров для клиентского .conf: сначала известные
// в каноническом порядке, затем нераспознанные в порядке появления в конфиге сервера.
// Возвращаются только те ключи, которые реально есть в params.AWGParams.
func clientParamOrder(params *ServerParams) []string {
	if params == nil || len(params.AWGParams) == 0 {
		return nil
	}
	order := make([]string, 0, len(params.AWGParams))
	for _, spec := range awgParamSpecs {
		if _, ok := params.AWGParams[spec.Key]; ok {
			order = append(order, spec.Key)
		}
	}
	for _, key := range params.ExtraParamOrder {
		if _, ok := params.AWGParams[key]; ok {
			order = append(order, key)
		}
	}
	return order
}

// serverParamOrder — порядок параметров для серверного конфига при установке:
// только те, что версия v понимает и что имеет смысл писать на стороне сервера.
func serverParamOrder(v AWGVersion) []string {
	order := make([]string, 0, len(awgParamSpecs))
	for _, spec := range awgParamSpecs {
		if !spec.Server || !versionHasParam(v, spec.MinVer) {
			continue
		}
		order = append(order, spec.Key)
	}
	return order
}

// --- Детект версии на сервере ---

// AWGVersionInfo — то, что удалось выяснить о версии AWG на сервере.
type AWGVersionInfo struct {
	Version  AWGVersion
	ToolsRaw string // "3.0.20260730"
	KmodRaw  string // "3.0.20260731-04"; пусто в docker (там userspace amneziawg-go)
}

var (
	// "amneziawg-tools v3.0.20260730", "wireguard-tools v1.0.20210914"
	toolsVersionRe = regexp.MustCompile(`(?i)(?:amneziawg|wireguard)[a-z-]*\s+v?(\d+)\.(\d+)(?:\.([\w.-]+))?`)
	// "version:        3.0.20260731-04"
	kmodVersionRe = regexp.MustCompile(`(?im)^\s*version:\s*(\d+)\.(\d+)(?:\.([\w.-]+))?`)
)

// parseToolsVersion разбирает вывод `awg --version`.
func parseToolsVersion(out string) (AWGVersion, string) {
	return matchVersion(toolsVersionRe, out)
}

// parseKmodVersion разбирает строку `version:` из `modinfo amneziawg`.
func parseKmodVersion(out string) (AWGVersion, string) {
	return matchVersion(kmodVersionRe, out)
}

func matchVersion(re *regexp.Regexp, out string) (AWGVersion, string) {
	m := re.FindStringSubmatch(out)
	if m == nil {
		return AWGVersionUnknown, ""
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return AWGVersionUnknown, ""
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return AWGVersionUnknown, ""
	}

	raw := m[1] + "." + m[2]
	if m[3] != "" {
		raw += "." + m[3]
	}

	switch {
	case major == 1 && minor == 5:
		return AWGVersion15, raw
	case major <= 1:
		return AWGVersion1, raw
	default:
		return AWGVersion(major), raw
	}
}

// parseAWGVersionOutput — чистая часть detectAWGVersion: сводит версии tools и
// модуля ядра в одну эффективную.
//
// Эффективная версия — более ранняя из двух: tools 3.0 распарсят
// HeaderProtectionKey и отправят его через netlink, но модуль 2.0 отвергнет
// неизвестный атрибут и интерфейс не поднимется. Если модуля нет (docker с
// userspace amneziawg-go) — берём версию tools.
func parseAWGVersionOutput(out string) AWGVersionInfo {
	toolsVer, toolsRaw := parseToolsVersion(out)
	kmodVer, kmodRaw := parseKmodVersion(out)

	info := AWGVersionInfo{ToolsRaw: toolsRaw, KmodRaw: kmodRaw}
	switch {
	case kmodVer == AWGVersionUnknown:
		info.Version = toolsVer
	case toolsVer == AWGVersionUnknown:
		info.Version = kmodVer
	default:
		info.Version = minAWGVersion(toolsVer, kmodVer)
	}
	return info
}

// detectAWGVersion опрашивает сервер ОДНОЙ командой: каждая SSH-сессия — это
// новый Dial (SSHRunTimeout, ssh.go), лишние обходятся дорого.
func detectAWGVersion(srv ServerConfig) (AWGVersionInfo, error) {
	const cmd = `sh -c 'awg --version 2>/dev/null; modinfo amneziawg 2>/dev/null | grep "^version:"'`
	out, err := execAWG(srv, cmd)
	if err != nil {
		return AWGVersionInfo{}, fmt.Errorf("определение версии AWG: %w", err)
	}
	info := parseAWGVersionOutput(out)
	if info.Version == AWGVersionUnknown {
		return info, fmt.Errorf("не удалось разобрать версию AWG: %s", strings.TrimSpace(out))
	}
	return info, nil
}

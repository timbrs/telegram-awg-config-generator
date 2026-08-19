package main

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

// AWGVersion — версия протокола AmneziaWG.
//
// Кодировка значения: мажорная версия без минорной — само число (1 → 1.0,
// 2 → 2.0, 3 → 3.0), с минорной — major*10+minor (15 → 1.5, 31 → 3.1).
// Значения попадают в config.yaml (`awg_version`), поэтому менять кодировку
// задним числом нельзя.
//
// Ветка 1.5 (J1-J3, Itime, I1-I5 отдельными полями) прожила два дня в июле 2025
// и была откачена — amneziawg-tools v1.0.20250706, «Reverted AWG 1.5 changes».
// Она стоит особняком, а не между 1.0 и 2.0, поэтому прямые сравнения `<`/`>`
// бессмысленны: набор параметров версии проверяйте через versionHasParam,
// а хронологию — через versionRank.
type AWGVersion int

const (
	AWGVersionUnknown AWGVersion = 0
	AWGVersion1       AWGVersion = 1  // Jc/Jmin/Jmax, S1-S2, H1-H4 скалярами
	AWGVersion15      AWGVersion = 15 // тупиковая ветка июля 2025: I1-I5, J1-J3, Itime
	AWGVersion2       AWGVersion = 2  // S3/S4, H1-H4 диапазонами, I1-I5 в виде CPS-тегов
	AWGVersion3       AWGVersion = 3  // HeaderProtectionKey, ContentPaddingAddition, тайминги
	AWGVersion31      AWGVersion = 31 // RandomTrailers, DisableCookies (tools v3.1.20260812)
)

// versionParts раскладывает значение на мажорную и минорную часть.
func versionParts(v AWGVersion) (major, minor int) {
	if v < 10 {
		return int(v), 0
	}
	return int(v) / 10, int(v) % 10
}

// awgVersionFromParts — обратная операция: (3, 1) → AWGVersion31.
func awgVersionFromParts(major, minor int) AWGVersion {
	if major < 1 {
		// wireguard-tools 0.x — до-AWG эпоха, набор параметров тот же, что у 1.0.
		return AWGVersion1
	}
	if minor <= 0 {
		return AWGVersion(major)
	}
	if minor > 9 {
		// Кодировка major*10+minor двузначных миноров не вмещает. Такой нумерации
		// у AWG не было; подрезаем, чтобы версия осталась в своей мажорной ветке
		// и не уехала рангом ниже более ранних релизов.
		minor = 9
	}
	return AWGVersion(major*10 + minor)
}

// versionRank — порядок версий по времени выпуска (1.0 → 1.5 → 2.0 → 3.0 → 3.1 → …).
// Нужен потому, что числовое значение AWGVersion15 и AWGVersion31 выбивается из
// хронологии: 15 стоит между 1 и 2, а 31 — сразу за 3.
func versionRank(v AWGVersion) int {
	if v == AWGVersionUnknown {
		return 0
	}
	major, minor := versionParts(v)
	return major*10 + minor // 1.0 → 10, 1.5 → 15, 2.0 → 20, 3.0 → 30, 3.1 → 31
}

// String — человекочитаемое имя версии для UI: «AWG 2.0», «AWG 3.1».
func (v AWGVersion) String() string {
	if v == AWGVersionUnknown {
		return "AWG ?"
	}
	major, minor := versionParts(v)
	return fmt.Sprintf("AWG %d.%d", major, minor)
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
	{"RandomTrailers", AWGVersion31, true}, {"DisableCookies", AWGVersion31, true},
}

// awgBoolParams — параметры-тумблеры (parse_bool в config.c: on/off или 0/1).
// Их значение — не число и не диапазон, поэтому эвристики версии обрабатывают
// их отдельно.
var awgBoolParams = map[string]bool{
	"RandomTrailers": true, "DisableCookies": true,
}

// awgToggleEnabled — включён ли тумблер. «off», «0» и пустая строка считаются
// выключенными: так же их трактует приложение AmneziaVPN (isAwgToggleEnabled в
// awgProtocolConfig.cpp), и выключенный тумблер не делает конфиг конфигом 3.1.
func awgToggleEnabled(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "", "off", "0":
		return false
	}
	return true
}

// awgParamMinVer — индекс awgParamSpecs по каноническому имени ключа.
var awgParamMinVer = func() map[string]AWGVersion {
	m := make(map[string]AWGVersion, len(awgParamSpecs))
	for _, spec := range awgParamSpecs {
		m[spec.Key] = spec.MinVer
	}
	return m
}()

// awgParamCanonical — имя в нижнем регистре → каноническое написание.
// Парсер awg-quick регистронезависим, поэтому в конфиге может стоять `jc = 4`;
// бот приводит такие ключи к каноническому виду, чтобы они не потерялись в
// clientParamOrder.
var awgParamCanonical = func() map[string]string {
	m := make(map[string]string, len(awgParamSpecs))
	for _, spec := range awgParamSpecs {
		m[strings.ToLower(spec.Key)] = spec.Key
	}
	return m
}()

// reservedInterfaceKeys — ключи [Interface], которые обрабатывает сам awg-quick
// или ядро (в нижнем регистре: awg-quick сравнивает имена без учёта регистра).
// Всё остальное в секции считается параметром обфускации AmneziaWG и зеркалится
// в клиентский конфиг как есть — так поддержка новых версий протокола не требует
// правок кода.
var reservedInterfaceKeys = map[string]bool{
	"privatekey": true, "listenport": true, "fwmark": true,
	"address": true, "dns": true, "mtu": true, "table": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true,
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
	return versionRank(minVer) <= versionRank(v)
}

// rangeValueRe — значение вида "100-200" (диапазон H-параметров в AWG 2.0).
var rangeValueRe = regexp.MustCompile(`^\d+-\d+$`)

// deriveConfigVersion определяет версию протокола по набору параметров в конфиге.
// Используется как фолбэк, когда `awg --version` на сервере недоступен.
func deriveConfigVersion(params *ServerParams) AWGVersion {
	if params == nil || len(params.AWGParams) == 0 {
		return AWGVersionUnknown
	}

	// Версии 3.0+ определяются по самому позднему из присутствующих параметров:
	// набор растёт от версии к версии, и одного RandomTrailers достаточно, чтобы
	// конфиг был конфигом 3.1. Параметры 1.0-2.0 сюда не входят — по ним версия
	// определяется эвристиками ниже (I1-I5 живут и в 1.5, и в 2.0).
	best := AWGVersionUnknown
	for key, val := range params.AWGParams {
		minVer, known := awgParamMinVer[key]
		if !known || versionRank(minVer) < versionRank(AWGVersion3) {
			continue
		}
		if awgBoolParams[key] && !awgToggleEnabled(val) {
			continue
		}
		if versionRank(minVer) > versionRank(best) {
			best = minVer
		}
	}
	if best != AWGVersionUnknown {
		return best
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
	ToolsRaw string // "3.1.20260812"
	KmodRaw  string // "3.1.20260812-01"; пусто в docker (там userspace amneziawg-go)
	// FromConfig — версию подняли по набору параметров в awg0.conf, потому что
	// `awg --version` назвался более старым. Нужно для UI: показать, откуда цифра.
	FromConfig bool
}

// withConfigVersion сводит версию, названную инструментами, с той, что следует
// из набора параметров конфига.
//
// Версию можно только поднять. `awg --version` систематически занижает её:
// src/version.h в amneziawg-tools не трогали с сентября 2021 по июнь 2026, и всё
// это время инструменты печатали «amneziawg-tools v1.0.20210914» — в том числе в
// контейнерах AmneziaVPN с полноценным AWG 2.0. Конфиг честнее: awg-quick с
// S3/S4 не поднял бы интерфейс на инструментах и модуле, которые их не знают.
//
// Понижать нельзя: конфиг 2.0 на сервере с tools 3.1 означает лишь, что админ не
// включил параметры 3.x, а не что сервер их не умеет.
func withConfigVersion(info AWGVersionInfo, cfgVer AWGVersion) AWGVersionInfo {
	if versionRank(cfgVer) > versionRank(info.Version) {
		info.Version = cfgVer
		info.FromConfig = true
	}
	return info
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

	// Минорная версия значима: 3.1 добавила RandomTrailers/DisableCookies, а 1.5
	// вообще стоит особняком. Схлопывать её к мажорной нельзя — иначе сервер с
	// tools 3.1 выглядел бы как 3.0 и в UI, и в versionHasParam.
	return awgVersionFromParts(major, minor), raw
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

// awgVersionProbeCmd опрашивает версию tools и модуля ядра за один заход.
//
// Завершающий `; true` обязателен: exit status пайплайна — это код grep, а без
// модуля ядра (docker с userspace amneziawg-go) grep ничего не находит и выходит
// с 1. SSHRun превратил бы это в ошибку и выбросил уже полученный вывод
// `awg --version`, из-за чего версия на docker-серверах не определялась бы никогда.
const awgVersionProbeCmd = `sh -c 'awg --version 2>/dev/null; modinfo amneziawg 2>/dev/null | grep "^version:"; true'`

// detectAWGVersion опрашивает сервер: версии tools и модуля ядра — одной
// командой (каждая SSH-сессия — это новый Dial, SSHRunTimeout в ssh.go), плюс
// чтение конфига, чтобы поднять заниженную версию инструментов (withConfigVersion).
//
// Детект вызывается только при добавлении сервера и по кнопке «Проверить версии»,
// на горячем пути (AddPeer, showStatus) версия берётся из кэша в config.yaml.
func detectAWGVersion(srv ServerConfig) (AWGVersionInfo, error) {
	out, err := execAWG(srv, awgVersionProbeCmd)
	if err != nil {
		return AWGVersionInfo{}, fmt.Errorf("определение версии AWG: %w", err)
	}
	info := parseAWGVersionOutput(out)

	if params, cfgErr := ReadServerConfig(srv); cfgErr == nil {
		info = withConfigVersion(info, params.Version)
	} else {
		log.Printf("AWG (%s): конфиг не прочитан, версия только по awg --version: %v", srv.Name, cfgErr)
	}

	if info.Version == AWGVersionUnknown {
		return info, fmt.Errorf("не удалось разобрать версию AWG: %s", strings.TrimSpace(out))
	}
	return info, nil
}

package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Name          string    `yaml:"name"`
	IP            string    `yaml:"ip"`
	EndpointIP    string    `yaml:"endpoint_ip,omitempty"` // публичный адрес для Endpoint в клиентских конфигах (обычно IPv4); если пусто — используется IP
	Login         string    `yaml:"login"`
	Pass          string    `yaml:"pass"`
	AllowedUIDs   []int64   `yaml:"allowed_uids"`
	ReportUIDs    []int64   `yaml:"report_uids"`
	LastConnected time.Time `yaml:"last_connected"`
	Mode          string    `yaml:"mode,omitempty"`              // "docker" (default) or "native"
	AWGConfDir    string    `yaml:"awg_conf_dir,omitempty"`      // path to AWG configs
	Port          int       `yaml:"port,omitempty"`              // AWG listen port (default 51820)
	NetIface      string    `yaml:"net_iface,omitempty"`         // main network interface (eth0)
	IPv6Subnet    string    `yaml:"ipv6_subnet,omitempty"`       // VPN IPv6 client subnet CIDR (e.g. 2a01:db8::4000/114)
	IPv6IfaceAddr string    `yaml:"ipv6_iface_addr,omitempty"`   // AWG interface IPv6 address (e.g. 2a01:db8::1/64), empty = same as IPv6Subnet
	Iface         string    `yaml:"iface,omitempty"`             // имя AWG-интерфейса, awg0 по умолчанию
	AWGVersion    int       `yaml:"awg_version,omitempty"`       // 1/15/2/3/31 — кэш детекта версии протокола (major*10+minor у минорных)
	AWGToolsVer   string    `yaml:"awg_tools_version,omitempty"` // "3.1.20260812" — для показа в UI
	DNS           string    `yaml:"dns,omitempty"`               // DNS для клиентских конфигов (через запятую)
}

type AppConfig struct {
	BotToken string         `yaml:"bot_token"`
	Servers  []ServerConfig `yaml:"servers"`
}

// EndpointHost возвращает адрес, который попадёт в Endpoint клиентских VPN-конфигов.
// Если задан EndpointIP (обычно публичный IPv4) — используется он, иначе IP,
// по которому бот подключается к серверу по SSH (может быть IPv6).
func (s ServerConfig) EndpointHost() string {
	if s.EndpointIP != "" {
		return s.EndpointIP
	}
	return s.IP
}

// IfaceName — имя AWG-интерфейса; awg0 по умолчанию (так называет его Amnezia).
// На сервере, настроенном вручную, интерфейс вполне может называться wg0.
func (s ServerConfig) IfaceName() string {
	if s.Iface != "" {
		return s.Iface
	}
	return defaultIfaceName
}

// ProtoVersion — закэшированная версия протокола AWG на сервере.
func (s ServerConfig) ProtoVersion() AWGVersion {
	return AWGVersion(s.AWGVersion)
}

type ConfigManager struct {
	mu       sync.RWMutex
	config   AppConfig
	filePath string
	modTime  time.Time
}

func NewConfigManager(path string) *ConfigManager {
	return &ConfigManager{filePath: path}
}

func (cm *ConfigManager) Load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.loadLocked()
}

func (cm *ConfigManager) loadLocked() error {
	data, err := os.ReadFile(cm.filePath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать %s: %w", cm.filePath, err)
	}

	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("не удалось распарсить %s: %w", cm.filePath, err)
	}

	info, err := os.Stat(cm.filePath)
	if err != nil {
		return fmt.Errorf("не удалось получить stat %s: %w", cm.filePath, err)
	}

	cm.config = cfg
	cm.modTime = info.ModTime()
	return nil
}

func (cm *ConfigManager) CheckReload() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	info, err := os.Stat(cm.filePath)
	if err != nil {
		return fmt.Errorf("не удалось получить stat %s: %w", cm.filePath, err)
	}

	if info.ModTime().After(cm.modTime) {
		return cm.loadLocked()
	}
	return nil
}

// Get возвращает НЕЗАВИСИМУЮ копию конфига.
//
// Копировать обязательно: AppConfig копируется по значению, но срез Servers
// продолжал бы указывать на тот же backing array, а мутаторы (SetAWGInfo,
// RenameServer, AddAllowedUID, …) правят его элементы на месте. Вызывающие
// держат сервер по указателю (resolveServer) и читают его без блокировки —
// это была гонка на заголовках строк, вплоть до порванного имени интерфейса
// в команде `awg show`.
func (cm *ConfigManager) Get() AppConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config.clone()
}

// clone делает глубокую копию изменяемых частей конфига.
func (c AppConfig) clone() AppConfig {
	out := c
	out.Servers = make([]ServerConfig, len(c.Servers))
	copy(out.Servers, c.Servers)
	for i := range out.Servers {
		out.Servers[i].AllowedUIDs = append([]int64(nil), c.Servers[i].AllowedUIDs...)
		out.Servers[i].ReportUIDs = append([]int64(nil), c.Servers[i].ReportUIDs...)
	}
	return out
}

func (cm *ConfigManager) UpdateLastConnected(serverIdx int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	cm.config.Servers[serverIdx].LastConnected = time.Now()
	return cm.saveLocked()
}

func (cm *ConfigManager) RenameServer(serverIdx int, newName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	cm.config.Servers[serverIdx].Name = newName
	return cm.saveLocked()
}

// SetAWGInfo сохраняет результат детекта версии и имени интерфейса.
// Кэш нужен потому, что версия на сервере меняется независимо от бота
// (apt upgrade), а на горячем пути (AddPeer, showStatus) SSH-детект не делается.
func (cm *ConfigManager) SetAWGInfo(serverIdx int, info AWGVersionInfo, iface string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	srv := &cm.config.Servers[serverIdx]
	srv.AWGVersion = int(info.Version)
	srv.AWGToolsVer = info.ToolsRaw
	if iface == defaultIfaceName {
		srv.Iface = "" // дефолт в YAML не пишем
	} else if iface != "" {
		srv.Iface = iface
	}
	return cm.saveLocked()
}

func (cm *ConfigManager) ServersForUser(uid int64) []int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var indices []int
	for i, srv := range cm.config.Servers {
		for _, allowed := range srv.AllowedUIDs {
			if allowed == uid {
				indices = append(indices, i)
				break
			}
		}
	}
	return indices
}

// saveLocked marshals and writes config to disk. Must be called under cm.mu write lock.
func (cm *ConfigManager) saveLocked() error {
	data, err := yaml.Marshal(&cm.config)
	if err != nil {
		return fmt.Errorf("сериализация конфига: %w", err)
	}
	if err := os.WriteFile(cm.filePath, data, 0644); err != nil {
		return fmt.Errorf("запись конфига: %w", err)
	}
	info, err := os.Stat(cm.filePath)
	if err == nil {
		cm.modTime = info.ModTime()
	}
	return nil
}

func (cm *ConfigManager) AddServer(srv ServerConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.config.Servers = append(cm.config.Servers, srv)
	return cm.saveLocked()
}

func (cm *ConfigManager) AddAllowedUID(serverIdx int, uid int64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	// Check duplicate
	for _, u := range cm.config.Servers[serverIdx].AllowedUIDs {
		if u == uid {
			return nil
		}
	}

	cm.config.Servers[serverIdx].AllowedUIDs = append(cm.config.Servers[serverIdx].AllowedUIDs, uid)
	return cm.saveLocked()
}

func (cm *ConfigManager) RemoveAllowedUID(serverIdx int, uid int64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	uids := cm.config.Servers[serverIdx].AllowedUIDs
	var filtered []int64
	for _, u := range uids {
		if u != uid {
			filtered = append(filtered, u)
		}
	}
	cm.config.Servers[serverIdx].AllowedUIDs = filtered

	// Also remove from report_uids
	rids := cm.config.Servers[serverIdx].ReportUIDs
	var filteredR []int64
	for _, u := range rids {
		if u != uid {
			filteredR = append(filteredR, u)
		}
	}
	cm.config.Servers[serverIdx].ReportUIDs = filteredR

	return cm.saveLocked()
}

func (cm *ConfigManager) AddReportUID(serverIdx int, uid int64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	for _, u := range cm.config.Servers[serverIdx].ReportUIDs {
		if u == uid {
			return nil
		}
	}

	cm.config.Servers[serverIdx].ReportUIDs = append(cm.config.Servers[serverIdx].ReportUIDs, uid)
	return cm.saveLocked()
}

func (cm *ConfigManager) RemoveReportUID(serverIdx int, uid int64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	rids := cm.config.Servers[serverIdx].ReportUIDs
	var filtered []int64
	for _, u := range rids {
		if u != uid {
			filtered = append(filtered, u)
		}
	}
	cm.config.Servers[serverIdx].ReportUIDs = filtered
	return cm.saveLocked()
}

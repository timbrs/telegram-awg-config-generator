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
	Login         string    `yaml:"login"`
	Pass          string    `yaml:"pass"`
	AllowedUIDs   []int64   `yaml:"allowed_uids"`
	LastConnected time.Time `yaml:"last_connected"`
}

type AppConfig struct {
	BotToken string         `yaml:"bot_token"`
	Servers  []ServerConfig `yaml:"servers"`
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

func (cm *ConfigManager) Get() AppConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config
}

func (cm *ConfigManager) UpdateLastConnected(serverIdx int) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	cm.config.Servers[serverIdx].LastConnected = time.Now()

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

func (cm *ConfigManager) RenameServer(serverIdx int, newName string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if serverIdx < 0 || serverIdx >= len(cm.config.Servers) {
		return fmt.Errorf("индекс сервера %d вне диапазона", serverIdx)
	}

	cm.config.Servers[serverIdx].Name = newName

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

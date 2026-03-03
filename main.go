package main

import (
	"log"
)

func main() {
	cfg := NewConfigManager("config.yaml")
	if err := cfg.Load(); err != nil {
		log.Fatalf("Ошибка загрузки конфига: %v", err)
	}

	appCfg := cfg.Get()
	log.Printf("Конфиг загружен: %d сервер(ов)", len(appCfg.Servers))

	bot, err := NewBot(cfg)
	if err != nil {
		log.Fatalf("Ошибка создания бота: %v", err)
	}

	bot.Start()
}

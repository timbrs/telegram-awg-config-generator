package main

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	tele "gopkg.in/telebot.v3"
)

type Bot struct {
	bot        *tele.Bot
	cfg        *ConfigManager
	state      *State
	pendingNew map[int64]bool // uid -> waiting for peer name
	mu         sync.RWMutex
}

func NewBot(cfg *ConfigManager) (*Bot, error) {
	appCfg := cfg.Get()

	pref := tele.Settings{
		Token:  appCfg.BotToken,
		Poller: &tele.LongPoller{Timeout: 10 * time.Second},
	}

	b, err := tele.NewBot(pref)
	if err != nil {
		return nil, fmt.Errorf("создание бота: %w", err)
	}

	return &Bot{
		bot:        b,
		cfg:        cfg,
		state:      LoadState(),
		pendingNew: make(map[int64]bool),
	}, nil
}

func (b *Bot) Start() {
	handler := func(c tele.Context) error {
		return b.handleMessage(c)
	}

	// Register slash commands
	b.bot.Handle("/start", handler)
	b.bot.Handle("/status", handler)
	b.bot.Handle("/new", handler)
	b.bot.Handle("/delete", handler)
	b.bot.Handle("/server", handler)
	b.bot.Handle("/cancel", handler)

	// Also handle plain text (commands without slash)
	b.bot.Handle(tele.OnText, handler)

	// Set bot command menu for Telegram UI hints
	_ = b.bot.SetCommands([]tele.Command{
		{Text: "status", Description: "Список ключей и их статус"},
		{Text: "new", Description: "Создать новый ключ"},
		{Text: "delete", Description: "Удалить ключ"},
		{Text: "server", Description: "Выбор активного сервера"},
		{Text: "cancel", Description: "Отменить текущую операцию"},
	})

	log.Println("Бот запущен")
	b.bot.Start()
}

func (b *Bot) handleMessage(c tele.Context) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC в обработчике: %v", r)
			_ = c.Send(fmt.Sprintf("❌ Внутренняя ошибка: %v", r))
		}
	}()

	// Only private chats
	if c.Chat().Type != tele.ChatPrivate {
		return nil
	}

	// Reload config if changed
	if err := b.cfg.CheckReload(); err != nil {
		log.Printf("Ошибка перезагрузки конфига: %v", err)
	}

	uid := c.Sender().ID
	text := strings.TrimSpace(c.Message().Text)

	// Remove leading / if present
	if strings.HasPrefix(text, "/") {
		text = text[1:]
	}

	// Remove @botname suffix from commands
	if atIdx := strings.Index(text, "@"); atIdx > 0 {
		spaceIdx := strings.Index(text[atIdx:], " ")
		if spaceIdx > 0 {
			text = text[:atIdx] + text[atIdx+spaceIdx:]
		} else {
			text = text[:atIdx]
		}
	}

	parts := strings.Fields(text)
	if len(parts) == 0 {
		return nil
	}

	cmd := strings.ToLower(parts[0])

	// Handle /delete_N format (clickable delete from list)
	if strings.HasPrefix(cmd, "delete_") {
		idStr := strings.TrimPrefix(cmd, "delete_")
		parts = []string{"delete", idStr}
		cmd = "delete"
	}

	// Handle /server_N format (clickable server select)
	if strings.HasPrefix(cmd, "server_") {
		numStr := strings.TrimPrefix(cmd, "server_")
		parts = []string{"server", numStr}
		cmd = "server"
	}

	// /cancel — отмена текущей операции, возврат в главное меню
	if cmd == "cancel" {
		b.mu.Lock()
		delete(b.pendingNew, uid)
		b.mu.Unlock()
		return b.sendMainMenu(c, uid)
	}

	// Any command cancels pending state (except free text which is the name)
	isCommand := cmd == "start" || cmd == "status" || cmd == "new" || cmd == "delete" || cmd == "server"

	// Check if user is in "pending new" state and sent a name (not a command)
	if !isCommand {
		b.mu.RLock()
		pending := b.pendingNew[uid]
		b.mu.RUnlock()
		if pending {
			b.mu.Lock()
			delete(b.pendingNew, uid)
			b.mu.Unlock()

			srv, err := b.resolveServer(uid)
			if err != nil {
				return c.Send(err.Error())
			}
			return b.handleNewCreate(c, *srv, parts[0])
		}
		return c.Send("Неизвестная команда. Доступны: /status, /new, /delete, /server")
	}

	// If user sends another command, cancel pending state
	b.mu.Lock()
	delete(b.pendingNew, uid)
	b.mu.Unlock()

	// /start command — same as main menu
	if cmd == "start" {
		return b.sendMainMenu(c, uid)
	}

	// /server doesn't need SSH, handle separately
	if cmd == "server" {
		return b.handleServer(c, parts[1:])
	}

	// Access check
	srv, err := b.resolveServer(uid)
	if err != nil {
		return c.Send(err.Error())
	}

	switch cmd {
	case "status":
		return b.handleStatus(c, *srv)
	case "new":
		return b.handleNew(c, uid, *srv)
	case "delete":
		return b.handleDelete(c, *srv, parts[1:])
	default:
		return c.Send("Неизвестная команда. Доступны: /status, /new, /delete, /server")
	}
}

func (b *Bot) resolveServer(uid int64) (*ServerConfig, error) {
	indices := b.cfg.ServersForUser(uid)

	if len(indices) == 0 {
		return nil, fmt.Errorf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid)
	}

	if len(indices) == 1 {
		cfg := b.cfg.Get()
		return &cfg.Servers[indices[0]], nil
	}

	activeIdx, ok := b.state.GetActiveServer(uid)
	if !ok {
		return nil, fmt.Errorf("У вас доступно %d серверов. Используйте /server <#> для выбора.", len(indices))
	}

	cfg := b.cfg.Get()
	for _, idx := range indices {
		if idx == activeIdx {
			return &cfg.Servers[idx], nil
		}
	}

	return nil, fmt.Errorf("Выбранный сервер больше не доступен. Используйте /server <#> для выбора.")
}

func sendLoading(c tele.Context) *tele.Message {
	msg, err := c.Bot().Send(c.Chat(), "⏳ Загружаю...")
	if err != nil {
		log.Printf("Ошибка отправки 'Загружаю...': %v", err)
	}
	return msg
}

func (b *Bot) sendMainMenu(c tele.Context, uid int64) error {
	cfg := b.cfg.Get()
	indices := b.cfg.ServersForUser(uid)

	var serverLine string
	if len(indices) == 0 {
		serverLine = fmt.Sprintf("Нет доступных серверов (UID: %d)", uid)
	} else if len(indices) == 1 {
		srv := cfg.Servers[indices[0]]
		serverLine = fmt.Sprintf("🖥 Сервер: %s (%s) /server", srv.Name, srv.IP)
	} else {
		activeIdx, ok := b.state.GetActiveServer(uid)
		if ok {
			srv := cfg.Servers[activeIdx]
			serverLine = fmt.Sprintf("🖥 Сервер: %s (%s) — сменить: /server", srv.Name, srv.IP)
		} else {
			serverLine = "🖥 Сервер не выбран — выбрать: /server"
		}
	}

	return c.Send(fmt.Sprintf("%s\n\n/status — ключи\n/new — создать\n/delete — удалить", serverLine))
}

func editResult(bot *tele.Bot, msg *tele.Message, text string) {
	if msg == nil {
		return
	}
	_, err := bot.Edit(msg, text)
	if err != nil {
		log.Printf("Ошибка редактирования сообщения: %v", err)
	}
}

// statusIcon returns emoji based on handshake recency:
//
//	🤝 — active (within 7 days)
//	💤 — stale (connected before, but >7 days ago)
//	🆕 — never connected
func statusIcon(handshake string) string {
	if handshake == "never" {
		return "🆕"
	}
	h := strings.TrimSuffix(handshake, " ago")
	if strings.Contains(h, "week") || strings.Contains(h, "month") || strings.Contains(h, "year") {
		return "💤"
	}
	for _, p := range strings.Split(h, ",") {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) >= 2 && (fields[1] == "day" || fields[1] == "days") {
			n, err := strconv.Atoi(fields[0])
			if err == nil && n >= 7 {
				return "💤"
			}
		}
	}
	return "🤝"
}

// formatHandshake converts verbose "1 hour, 12 minutes, 45 seconds ago" to compact "01:12:45 ago"
func formatHandshake(hs string) string {
	if hs == "never" {
		return hs
	}
	h := strings.TrimSuffix(hs, " ago")
	days, hours, mins, secs := 0, 0, 0, 0
	for _, part := range strings.Split(h, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		unit := fields[1]
		switch {
		case strings.HasPrefix(unit, "day"):
			days = n
		case strings.HasPrefix(unit, "hour"):
			hours = n
		case strings.HasPrefix(unit, "minute"):
			mins = n
		case strings.HasPrefix(unit, "second"):
			secs = n
		case strings.HasPrefix(unit, "week"):
			days += n * 7
		case strings.HasPrefix(unit, "month"):
			days += n * 30
		case strings.HasPrefix(unit, "year"):
			days += n * 365
		}
	}
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d ago", days, hours, mins, secs)
	}
	return fmt.Sprintf("%02d:%02d:%02d ago", hours, mins, secs)
}

func formatError(srv ServerConfig, cmd string, err error, output string) string {
	result := fmt.Sprintf("❌ %s", err.Error())
	if cmd != "" {
		result += fmt.Sprintf("\n\nКоманда: %s", cmd)
	}
	result += fmt.Sprintf("\nСервер: %s (%s)", srv.Name, srv.IP)
	if output != "" {
		result += fmt.Sprintf("\nОтвет: %s", output)
	}
	return result
}

func (b *Bot) handleStatus(c tele.Context, srv ServerConfig) error {
	msg := sendLoading(c)

	clients, err := ListClients(srv)
	if err != nil {
		editResult(c.Bot(), msg, formatError(srv, "", err, ""))
		return nil
	}

	if len(clients) == 0 {
		editResult(c.Bot(), msg, fmt.Sprintf("📋 Сервер: %s /server\n\nКлиенты не найдены.", srv.Name))
		return nil
	}

	// Fetch live stats from awg show
	liveStats, statsErr := AWGShow(srv)
	if statsErr != nil {
		log.Printf("awg show failed: %v", statsErr)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📋 Сервер: %s /server\n\n", srv.Name))
	for _, cl := range clients {
		handshake := "never"
		rx := "0 B"
		tx := "0 B"
		if liveStats != nil {
			if ps, ok := liveStats[cl.ClientID]; ok {
				if ps.LatestHandshake != "" {
					handshake = ps.LatestHandshake
				}
				if ps.TransferRx != "" {
					rx = ps.TransferRx
				}
				if ps.TransferTx != "" {
					tx = ps.TransferTx
				}
			}
		}
		icon := statusIcon(handshake)
		sb.WriteString(fmt.Sprintf("#%d %s  %s%s  ↓%s ↑%s\n", cl.ID, cl.UserData.ClientName, icon, formatHandshake(handshake), rx, tx))
	}
	sb.WriteString("Добавить: /new")

	editResult(c.Bot(), msg, sb.String())
	return nil
}

func (b *Bot) handleNew(c tele.Context, uid int64, srv ServerConfig) error {
	b.mu.Lock()
	b.pendingNew[uid] = true
	b.mu.Unlock()

	return c.Send(fmt.Sprintf("📝 Новый ключ на сервере %s\nВведите имя (или /cancel для отмены):", srv.Name))
}

func (b *Bot) handleNewCreate(c tele.Context, srv ServerConfig, name string) error {
	msg := sendLoading(c)

	clientConf, err := AddPeer(srv, name)
	if err != nil {
		editResult(c.Bot(), msg, formatError(srv, "", err, ""))
		return nil
	}

	editResult(c.Bot(), msg, fmt.Sprintf("✅ Ключ \"%s\" создан на сервере %s", name, srv.Name))

	// Send config as file
	confCaption := "📄 Конфигурация AmneziaWG\n\n" +
		"Скачайте приложение AmneziaWG:\n" +
		"  Android — play.google.com/store/apps/details?id=org.amnezia.awg\n" +
		"  iPhone — apps.apple.com/app/amneziawg/id6478942365\n\n" +
		"Откройте приложение → нажмите «+» → «Импорт из файла» → выберите этот .conf файл."
	doc := &tele.Document{
		File:     tele.FromReader(strings.NewReader(clientConf)),
		FileName: name + ".conf",
		Caption:  confCaption,
	}
	if err := c.Send(doc); err != nil {
		return err
	}

	// Send QR code
	png, err := qrcode.Encode(clientConf, qrcode.Medium, 256)
	if err != nil {
		log.Printf("QR generation failed: %v", err)
		return nil
	}
	qrCaption := "📷 Либо QR-код конфигурации\n\n" +
		"Откройте AmneziaWG → нажмите «+» → «Сканировать QR-код» → наведите камеру на это изображение."
	photo := &tele.Photo{
		File:    tele.FromReader(bytes.NewReader(png)),
		Caption: qrCaption,
	}
	return c.Send(photo)
}

func (b *Bot) handleDelete(c tele.Context, srv ServerConfig, args []string) error {
	if len(args) == 0 {
		// No ID — show list with delete commands
		msg := sendLoading(c)

		clients, err := ListClients(srv)
		if err != nil {
			editResult(c.Bot(), msg, formatError(srv, "", err, ""))
			return nil
		}

		if len(clients) == 0 {
			editResult(c.Bot(), msg, fmt.Sprintf("📋 Сервер: %s /server\n\nКлиенты не найдены.", srv.Name))
			return nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("🗑 Удаление — сервер: %s\n\n", srv.Name))
		for _, cl := range clients {
			sb.WriteString(fmt.Sprintf("#%d %s — %s\n", cl.ID, cl.UserData.ClientName, cl.UserData.AllowedIPs))
			sb.WriteString(fmt.Sprintf("   🤝 %s  /delete_%d\n\n", cl.UserData.LatestHandshake, cl.ID))
		}
		sb.WriteString("Назад: /cancel")

		editResult(c.Bot(), msg, sb.String())
		return nil
	}

	id, err := strconv.Atoi(args[0])
	if err != nil {
		return c.Send("❌ ID должен быть числом.\nПример: /delete 1")
	}

	msg := sendLoading(c)

	clients, err := ListClients(srv)
	if err != nil {
		editResult(c.Bot(), msg, formatError(srv, "", err, ""))
		return nil
	}

	if id < 1 || id > len(clients) {
		editResult(c.Bot(), msg, fmt.Sprintf("❌ Неверный ID: %d. Доступны ID от 1 до %d.", id, len(clients)))
		return nil
	}

	target := clients[id-1]
	err = RemovePeer(srv, target.ClientID)
	if err != nil {
		editResult(c.Bot(), msg, formatError(srv, "", err, ""))
		return nil
	}

	editResult(c.Bot(), msg, fmt.Sprintf("✅ Ключ #%d (%s) удалён с сервера %s", id, target.UserData.ClientName, srv.Name))
	return nil
}

func (b *Bot) handleServer(c tele.Context, args []string) error {
	uid := c.Sender().ID
	indices := b.cfg.ServersForUser(uid)

	if len(indices) == 0 {
		return c.Send(fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid))
	}

	cfg := b.cfg.Get()

	if len(args) == 0 {
		var sb strings.Builder
		sb.WriteString("Доступные серверы:\n\n")
		for i, idx := range indices {
			srv := cfg.Servers[idx]
			sb.WriteString(fmt.Sprintf("%d. %s (%s) — /server_%d\n", i+1, srv.Name, srv.IP, i+1))
		}
		return c.Send(sb.String())
	}

	num, err := strconv.Atoi(args[0])
	if err != nil || num < 1 || num > len(indices) {
		return c.Send(fmt.Sprintf("❌ Укажите номер от 1 до %d.", len(indices)))
	}

	serverIdx := indices[num-1]
	b.state.SetActiveServer(uid, serverIdx)
	if err := b.state.Save(); err != nil {
		log.Printf("Ошибка сохранения state: %v", err)
	}

	// Update last_connected in config
	if err := b.cfg.UpdateLastConnected(serverIdx); err != nil {
		log.Printf("Ошибка обновления last_connected: %v", err)
	}

	srv := cfg.Servers[serverIdx]
	return c.Send(fmt.Sprintf("✅ Активный сервер: %s (%s)\n\nСменить: /server\n\n/status — ключи\n/new — создать\n/delete — удалить", srv.Name, srv.IP))
}

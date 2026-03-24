package main

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	tele "gopkg.in/telebot.v3"
)

// Screen represents the current UI state for a user session.
type Screen int

const (
	ScreenMain                Screen = iota
	ScreenStatus                     // status displayed
	ScreenNewPrompt                  // waiting for new key name input
	ScreenDeletePrompt               // showing list, waiting for delete number
	ScreenRenamePrompt               // showing list, waiting for rename number
	ScreenRenamePending              // rename number chosen, waiting for new name
	ScreenServerList                 // server selection
	ScreenServerRenamePrompt         // server rename: pick which server
	ScreenServerRenamePending        // server rename: waiting for new name
)

// UserSession tracks the current UI state for a user.
type UserSession struct {
	Screen            Screen
	MessageID         int // ID of the "menu message" we keep editing
	ChatID            int64
	PendingClientID   string // pubKey for rename
	PendingClientName string // current name for rename
	PendingServerIdx  int    // server index for server rename
	PendingUserMsgIDs []int  // user message IDs to delete after rename
	Page              int    // current page for paginated lists (0-based)
}

const clientsPerPage = 30

// Inline button definitions (Unique must be ≤64 bytes).
var (
	btnMenu         = tele.InlineButton{Unique: "menu"}
	btnStatus       = tele.InlineButton{Unique: "st"}
	btnRefresh      = tele.InlineButton{Unique: "ref"}
	btnNew          = tele.InlineButton{Unique: "new"}
	btnDeleteList   = tele.InlineButton{Unique: "dls"}
	btnRenameList   = tele.InlineButton{Unique: "rls"}
	btnServerList   = tele.InlineButton{Unique: "svl"}
	btnServerSel    = tele.InlineButton{Unique: "sv"}
	btnServerRename = tele.InlineButton{Unique: "svrn"}
	btnServerRenSel = tele.InlineButton{Unique: "svr"}
	btnPagePrev     = tele.InlineButton{Unique: "ppv"}
	btnPageNext     = tele.InlineButton{Unique: "pnx"}
	btnNoop         = tele.InlineButton{Unique: "noop"}
)

type Bot struct {
	bot      *tele.Bot
	cfg      *ConfigManager
	state    *State
	sessions map[int64]*UserSession
	mu       sync.RWMutex
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
		bot:      b,
		cfg:      cfg,
		state:    LoadState(),
		sessions: make(map[int64]*UserSession),
	}, nil
}

func (b *Bot) getSession(uid, chatID int64) *UserSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[uid]
	if !ok {
		s = &UserSession{ChatID: chatID}
		b.sessions[uid] = s
	}
	s.ChatID = chatID
	return s
}

func (b *Bot) Start() {
	// Middleware: private chats only + config reload + panic recovery
	b.bot.Use(func(next tele.HandlerFunc) tele.HandlerFunc {
		return func(c tele.Context) error {
			if c.Chat().Type != tele.ChatPrivate {
				return nil
			}
			if err := b.cfg.CheckReload(); err != nil {
				log.Printf("Ошибка перезагрузки конфига: %v", err)
			}
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PANIC в обработчике: %v", r)
				}
			}()
			return next(c)
		}
	})

	// Text commands
	b.bot.Handle("/start", b.cmdStart)
	b.bot.Handle("/cancel", b.cmdCancel)
	b.bot.Handle(tele.OnText, b.onText)

	// Callback handlers
	b.bot.Handle(&btnMenu, b.cbMenu)
	b.bot.Handle(&btnStatus, b.cbStatus)
	b.bot.Handle(&btnRefresh, b.cbRefresh)
	b.bot.Handle(&btnNew, b.cbNew)
	b.bot.Handle(&btnDeleteList, b.cbDeleteList)
	b.bot.Handle(&btnRenameList, b.cbRenameList)
	b.bot.Handle(&btnServerList, b.cbServerList)
	b.bot.Handle(&btnServerSel, b.cbServerSelect)
	b.bot.Handle(&btnServerRename, b.cbServerRename)
	b.bot.Handle(&btnServerRenSel, b.cbServerRenameSelect)
	b.bot.Handle(&btnPagePrev, b.cbPagePrev)
	b.bot.Handle(&btnPageNext, b.cbPageNext)
	b.bot.Handle(&btnNoop, func(c tele.Context) error { return c.Respond() })

	_ = b.bot.SetCommands([]tele.Command{
		{Text: "start", Description: "Главное меню"},
		{Text: "cancel", Description: "Отменить текущую операцию"},
	})

	b.startReportScheduler()

	log.Println("Бот запущен")
	b.bot.Start()
}

// editOrSend tries to edit the session's menu message; falls back to sending a new one.
func (b *Bot) editOrSend(s *UserSession, bot *tele.Bot, text string, markup *tele.ReplyMarkup) error {
	if s.MessageID != 0 {
		msg := &tele.Message{ID: s.MessageID, Chat: &tele.Chat{ID: s.ChatID}}
		var err error
		if markup != nil {
			_, err = bot.Edit(msg, text, markup)
		} else {
			_, err = bot.Edit(msg, text)
		}
		if err == nil {
			return nil
		}
		log.Printf("Edit failed (msg %d): %v", s.MessageID, err)
	}

	var sent *tele.Message
	var err error
	if markup != nil {
		sent, err = bot.Send(&tele.Chat{ID: s.ChatID}, text, markup)
	} else {
		sent, err = bot.Send(&tele.Chat{ID: s.ChatID}, text)
	}
	if err != nil {
		return err
	}
	s.MessageID = sent.ID
	return nil
}

// syncMessageID updates session's MessageID from callback context.
func syncMessageID(s *UserSession, c tele.Context) {
	if cb := c.Callback(); cb != nil && cb.Message != nil {
		s.MessageID = cb.Message.ID
	}
}

// --- Screen renderers ---

func (b *Bot) showMainMenu(s *UserSession, bot *tele.Bot, uid int64) error {
	return b.showMainMenuWithHeader(s, bot, uid, "")
}

func (b *Bot) showMainMenuWithHeader(s *UserSession, bot *tele.Bot, uid int64, header string) error {
	s.Screen = ScreenMain

	cfg := b.cfg.Get()
	indices := b.cfg.ServersForUser(uid)

	var serverLine string
	switch {
	case len(indices) == 0:
		serverLine = fmt.Sprintf("Нет доступных серверов (UID: %d)", uid)
	case len(indices) == 1:
		srv := cfg.Servers[indices[0]]
		serverLine = fmt.Sprintf("🖥 Сервер: %s (%s)", srv.Name, srv.IP)
	default:
		activeIdx, ok := b.state.GetActiveServer(uid)
		if ok {
			srv := cfg.Servers[activeIdx]
			serverLine = fmt.Sprintf("🖥 Сервер: %s (%s)", srv.Name, srv.IP)
		} else {
			serverLine = "🖥 Сервер не выбран"
		}
	}

	text := serverLine
	if header != "" {
		text = header + "\n\n" + serverLine
	}

	markup := &tele.ReplyMarkup{}
	rows := []tele.Row{
		{markup.Data("📋 Статус", btnStatus.Unique), markup.Data("➕ Новый", btnNew.Unique)},
		{markup.Data("🗑 Удалить", btnDeleteList.Unique), markup.Data("✏️ Rename", btnRenameList.Unique)},
	}
	if len(indices) > 1 {
		rows = append(rows, tele.Row{markup.Data("🖥 Сервер", btnServerList.Unique)})
	}
	markup.Inline(rows...)

	return b.editOrSend(s, bot, text, markup)
}

// showLoading re-renders the main menu with an hourglass on the pressed button.
func (b *Bot) showLoading(s *UserSession, bot *tele.Bot, uid int64, loadingBtn string) {
	cfg := b.cfg.Get()
	indices := b.cfg.ServersForUser(uid)

	var serverLine string
	switch {
	case len(indices) == 0:
		serverLine = fmt.Sprintf("Нет доступных серверов (UID: %d)", uid)
	case len(indices) == 1:
		srv := cfg.Servers[indices[0]]
		serverLine = fmt.Sprintf("🖥 Сервер: %s (%s)", srv.Name, srv.IP)
	default:
		activeIdx, ok := b.state.GetActiveServer(uid)
		if ok {
			srv := cfg.Servers[activeIdx]
			serverLine = fmt.Sprintf("🖥 Сервер: %s (%s)", srv.Name, srv.IP)
		} else {
			serverLine = "🖥 Сервер не выбран"
		}
	}

	type btnDef struct {
		label  string
		unique string
	}
	buttons := []btnDef{
		{"📋 Статус", btnStatus.Unique},
		{"➕ Новый", btnNew.Unique},
		{"🗑 Удалить", btnDeleteList.Unique},
		{"✏️ Rename", btnRenameList.Unique},
	}
	for i, bd := range buttons {
		if bd.unique == loadingBtn {
			buttons[i].label = "⏳ " + bd.label
		}
	}

	markup := &tele.ReplyMarkup{}
	rows := []tele.Row{
		{markup.Data(buttons[0].label, buttons[0].unique), markup.Data(buttons[1].label, buttons[1].unique)},
		{markup.Data(buttons[2].label, buttons[2].unique), markup.Data(buttons[3].label, buttons[3].unique)},
	}
	if len(indices) > 1 {
		rows = append(rows, tele.Row{markup.Data("🖥 Сервер", btnServerList.Unique)})
	}
	markup.Inline(rows...)

	_ = b.editOrSend(s, bot, serverLine, markup)
}

// showStatusLoading shows hourglass on the Refresh button while data is loading.
func (b *Bot) showStatusLoading(s *UserSession, bot *tele.Bot) {
	if s.MessageID == 0 {
		return
	}
	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	rows = append(rows, tele.Row{
		markup.Data("⏳ Обновить", btnRefresh.Unique),
		markup.Data("↩ Меню", btnMenu.Unique),
	})
	markup.Inline(rows...)
	msg := &tele.Message{ID: s.MessageID, Chat: &tele.Chat{ID: s.ChatID}}
	_, _ = bot.EditReplyMarkup(msg, markup)
}

// paginateClients returns the slice of clients for the current page and fixes s.Page if out of bounds.
func paginateClients(clients []ClientEntry, s *UserSession) []ClientEntry {
	total := len(clients)
	if total == 0 {
		s.Page = 0
		return nil
	}
	maxPage := (total - 1) / clientsPerPage
	if s.Page > maxPage {
		s.Page = maxPage
	}
	if s.Page < 0 {
		s.Page = 0
	}
	start := s.Page * clientsPerPage
	end := start + clientsPerPage
	if end > total {
		end = total
	}
	return clients[start:end]
}

// pageRow builds pagination buttons row if needed.
func pageRow(markup *tele.ReplyMarkup, page, totalItems int) *tele.Row {
	if totalItems <= clientsPerPage {
		return nil
	}
	maxPage := (totalItems - 1) / clientsPerPage
	var btns []tele.Btn
	if page > 0 {
		btns = append(btns, markup.Data("⬅️", btnPagePrev.Unique))
	}
	btns = append(btns, markup.Data(fmt.Sprintf("%d/%d", page+1, maxPage+1), btnNoop.Unique))
	if page < maxPage {
		btns = append(btns, markup.Data("➡️", btnPageNext.Unique))
	}
	row := tele.Row(btns)
	return &row
}

func (b *Bot) showStatus(s *UserSession, bot *tele.Bot, srv ServerConfig) error {
	s.Screen = ScreenStatus

	clients, err := ListClients(srv)
	if err != nil {
		return b.showError(s, bot, formatError(srv, "", err, ""))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📋 Сервер: %s (всего: %d)\n\n", srv.Name, len(clients)))

	if len(clients) == 0 {
		sb.WriteString("Клиенты не найдены.")
	} else {
		liveStats, statsErr := AWGShow(srv)
		if statsErr != nil {
			log.Printf("awg show failed: %v", statsErr)
		}
		page := paginateClients(clients, s)
		for _, cl := range page {
			handshake := "never"
			rx, tx := "0 B", "0 B"
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
	}

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	if pr := pageRow(markup, s.Page, len(clients)); pr != nil {
		rows = append(rows, *pr)
	}
	rows = append(rows, tele.Row{
		markup.Data("🔄 Обновить", btnRefresh.Unique),
		markup.Data("↩ Меню", btnMenu.Unique),
	})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, sb.String(), markup)
}

func (b *Bot) showNewPrompt(s *UserSession, bot *tele.Bot, srv ServerConfig) error {
	s.Screen = ScreenNewPrompt
	text := fmt.Sprintf("📝 Новый ключ на сервере %s\nВведите имя ключа:", srv.Name)

	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})

	return b.editOrSend(s, bot, text, markup)
}

func (b *Bot) showDeletePrompt(s *UserSession, bot *tele.Bot, srv ServerConfig) error {
	s.Screen = ScreenDeletePrompt

	clients, err := ListClients(srv)
	if err != nil {
		return b.showError(s, bot, formatError(srv, "", err, ""))
	}
	if len(clients) == 0 {
		return b.showError(s, bot, fmt.Sprintf("📋 Сервер: %s\n\nКлиенты не найдены.", srv.Name))
	}

	liveStats, _ := AWGShow(srv)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🗑 Удаление ключа с сервера: %s (всего: %d)\n\n", srv.Name, len(clients)))
	page := paginateClients(clients, s)
	for _, cl := range page {
		handshake := "never"
		if liveStats != nil {
			if ps, ok := liveStats[cl.ClientID]; ok && ps.LatestHandshake != "" {
				handshake = ps.LatestHandshake
			}
		}
		icon := statusIcon(handshake)
		sb.WriteString(fmt.Sprintf("#%d %s  %s%s\n", cl.ID, cl.UserData.ClientName, icon, formatHandshake(handshake)))
	}
	sb.WriteString("\nВведите номер ключа для удаления:")

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	if pr := pageRow(markup, s.Page, len(clients)); pr != nil {
		rows = append(rows, *pr)
	}
	rows = append(rows, tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, sb.String(), markup)
}

func (b *Bot) showRenamePrompt(s *UserSession, bot *tele.Bot, srv ServerConfig) error {
	s.Screen = ScreenRenamePrompt

	clients, err := ListClients(srv)
	if err != nil {
		return b.showError(s, bot, formatError(srv, "", err, ""))
	}
	if len(clients) == 0 {
		return b.showError(s, bot, fmt.Sprintf("📋 Сервер: %s\n\nКлиенты не найдены.", srv.Name))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✏️ Переименование ключа на сервере: %s (всего: %d)\n\n", srv.Name, len(clients)))
	page := paginateClients(clients, s)
	for _, cl := range page {
		sb.WriteString(fmt.Sprintf("#%d %s\n", cl.ID, cl.UserData.ClientName))
	}
	sb.WriteString("\nВведите номер ключа для переименования:")

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	if pr := pageRow(markup, s.Page, len(clients)); pr != nil {
		rows = append(rows, *pr)
	}
	rows = append(rows, tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, sb.String(), markup)
}

func (b *Bot) showServerList(s *UserSession, bot *tele.Bot, uid int64) error {
	s.Screen = ScreenServerList

	indices := b.cfg.ServersForUser(uid)
	cfg := b.cfg.Get()

	if len(indices) == 0 {
		return b.showError(s, bot, fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid))
	}

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	for i, idx := range indices {
		srv := cfg.Servers[idx]
		text := fmt.Sprintf("%s (%s)", srv.Name, srv.IP)
		rows = append(rows, tele.Row{markup.Data(text, btnServerSel.Unique, strconv.Itoa(i+1))})
	}
	rows = append(rows, tele.Row{
		markup.Data("✏️ Переименовать", btnServerRename.Unique),
		markup.Data("↩ Меню", btnMenu.Unique),
	})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, "🖥 Выберите сервер:", markup)
}

func (b *Bot) showError(s *UserSession, bot *tele.Bot, text string) error {
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})
	return b.editOrSend(s, bot, text, markup)
}

// --- Command handlers ---

func (b *Bot) cmdStart(c tele.Context) error {
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	s.MessageID = 0 // force new message on /start
	return b.showMainMenu(s, c.Bot(), uid)
}

func (b *Bot) cmdCancel(c tele.Context) error {
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	return b.showMainMenu(s, c.Bot(), uid)
}

// --- Callback handlers ---

func (b *Bot) cbMenu(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	return b.showMainMenu(s, c.Bot(), uid)
}

func (b *Bot) cbStatus(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	s.Page = 0

	b.showLoading(s, c.Bot(), uid, btnStatus.Unique)

	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}
	return b.showStatus(s, c.Bot(), *srv)
}

func (b *Bot) cbRefresh(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	b.showStatusLoading(s, c.Bot())

	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}
	return b.showStatus(s, c.Bot(), *srv)
}

func (b *Bot) cbNew(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}
	return b.showNewPrompt(s, c.Bot(), *srv)
}

func (b *Bot) cbDeleteList(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	s.Page = 0

	b.showLoading(s, c.Bot(), uid, btnDeleteList.Unique)

	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}
	return b.showDeletePrompt(s, c.Bot(), *srv)
}

func (b *Bot) cbRenameList(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	s.Page = 0

	b.showLoading(s, c.Bot(), uid, btnRenameList.Unique)

	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}
	return b.showRenamePrompt(s, c.Bot(), *srv)
}

func (b *Bot) cbServerList(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	return b.showServerList(s, c.Bot(), uid)
}

func (b *Bot) cbServerSelect(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	data := strings.TrimSpace(c.Callback().Data)
	num, err := strconv.Atoi(data)
	if err != nil {
		return b.showError(s, c.Bot(), "❌ Ошибка выбора сервера.")
	}

	indices := b.cfg.ServersForUser(uid)
	if num < 1 || num > len(indices) {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Укажите номер от 1 до %d.", len(indices)))
	}

	serverIdx := indices[num-1]
	b.state.SetActiveServer(uid, serverIdx)
	if err := b.state.Save(); err != nil {
		log.Printf("Ошибка сохранения state: %v", err)
	}
	if err := b.cfg.UpdateLastConnected(serverIdx); err != nil {
		log.Printf("Ошибка обновления last_connected: %v", err)
	}

	return b.showMainMenu(s, c.Bot(), uid)
}

func (b *Bot) cbPagePrev(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	if s.Page > 0 {
		s.Page--
	}
	return b.redrawCurrentScreen(s, c.Bot(), uid)
}

func (b *Bot) cbPageNext(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	s.Page++
	return b.redrawCurrentScreen(s, c.Bot(), uid)
}

func (b *Bot) redrawCurrentScreen(s *UserSession, bot *tele.Bot, uid int64) error {
	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, bot, err.Error())
	}
	switch s.Screen {
	case ScreenStatus:
		return b.showStatus(s, bot, *srv)
	case ScreenDeletePrompt:
		return b.showDeletePrompt(s, bot, *srv)
	case ScreenRenamePrompt:
		return b.showRenamePrompt(s, bot, *srv)
	default:
		return b.showMainMenu(s, bot, uid)
	}
}

func (b *Bot) cbServerRename(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	return b.showServerRenameList(s, c.Bot(), uid)
}

func (b *Bot) showServerRenameList(s *UserSession, bot *tele.Bot, uid int64) error {
	s.Screen = ScreenServerRenamePrompt

	indices := b.cfg.ServersForUser(uid)
	cfg := b.cfg.Get()

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	for i, idx := range indices {
		srv := cfg.Servers[idx]
		text := fmt.Sprintf("%s (%s)", srv.Name, srv.IP)
		rows = append(rows, tele.Row{markup.Data(text, btnServerRenSel.Unique, strconv.Itoa(i+1))})
	}
	rows = append(rows, tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, "✏️ Выберите сервер для переименования:", markup)
}

func (b *Bot) cbServerRenameSelect(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	data := strings.TrimSpace(c.Callback().Data)
	num, err := strconv.Atoi(data)
	if err != nil {
		return b.showError(s, c.Bot(), "❌ Ошибка выбора сервера.")
	}

	indices := b.cfg.ServersForUser(uid)
	if num < 1 || num > len(indices) {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Укажите номер от 1 до %d.", len(indices)))
	}

	serverIdx := indices[num-1]
	cfg := b.cfg.Get()
	srv := cfg.Servers[serverIdx]

	s.Screen = ScreenServerRenamePending
	s.PendingServerIdx = serverIdx

	text := fmt.Sprintf("✏️ Переименование сервера: %s (%s)\nВведите новое имя:", srv.Name, srv.IP)
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerRename.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

// --- Text input handler ---

func sanitizeName(input string) string {
	s := strings.ReplaceAll(input, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func (b *Bot) onText(c tele.Context) error {
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	text := strings.TrimSpace(c.Message().Text)

	switch s.Screen {
	case ScreenNewPrompt:
		return b.handleNewCreate(c, s, text)
	case ScreenDeletePrompt:
		return b.handleDeleteByNumber(c, s, text)
	case ScreenRenamePrompt:
		return b.handleRenameSelectNumber(c, s, text)
	case ScreenRenamePending:
		return b.handleRenameExecute(c, s, text)
	case ScreenServerRenamePending:
		return b.handleServerRenameExecute(c, s, text)
	default:
		return nil // ignore unrelated text
	}
}

func (b *Bot) handleNewCreate(c tele.Context, s *UserSession, input string) error {
	name := sanitizeName(input)
	if name == "" {
		return b.showError(s, c.Bot(), "❌ Имя ключа не может быть пустым.")
	}

	uid := c.Sender().ID
	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	_ = b.editOrSend(s, c.Bot(), "⏳ Создаю ключ...", nil)

	clientConf, err := AddPeer(*srv, name)
	if err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}

	// Send config as file
	confCaption := "📄 Конфигурация AmneziaWG\n\n" +
		"Скачайте приложение AmneziaWG:\n" +
		"  Android — play.google.com/store/apps/details?id=org.amnezia.awg\n" +
		"  iPhone — apps.apple.com/app/amneziawg/id6478942365\n\n" +
		"Откройте приложение → нажмите «+» → «Импорт из файла» → выберите этот .conf файл."
	doc := &tele.Document{
		File:     tele.FromReader(strings.NewReader(clientConf)),
		FileName: sanitizeFileName(srv.Name),
		Caption:  confCaption,
	}
	_ = c.Send(doc)

	// Send QR code
	png, err := qrcode.Encode(clientConf, qrcode.Medium, 256)
	if err != nil {
		log.Printf("QR generation failed: %v", err)
	} else {
		qrCaption := "📷 Либо QR-код конфигурации\n\n" +
			"Откройте AmneziaWG → нажмите «+» → «Сканировать QR-код» → наведите камеру на это изображение."
		photo := &tele.Photo{
			File:    tele.FromReader(bytes.NewReader(png)),
			Caption: qrCaption,
		}
		_ = c.Send(photo)
	}

	// Show main menu with success header
	s.MessageID = 0 // force new message for menu
	return b.showMainMenuWithHeader(s, c.Bot(), uid, fmt.Sprintf("✅ Ключ \"%s\" создан на сервере %s", name, srv.Name))
}

func (b *Bot) handleDeleteByNumber(c tele.Context, s *UserSession, input string) error {
	num, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return b.showError(s, c.Bot(), "❌ Введите номер ключа (число).")
	}

	uid := c.Sender().ID
	srv, err2 := b.resolveServer(uid)
	if err2 != nil {
		return b.showError(s, c.Bot(), err2.Error())
	}

	_ = b.editOrSend(s, c.Bot(), "⏳ Удаляю...", nil)

	clients, err := ListClients(*srv)
	if err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}
	if num < 1 || num > len(clients) {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Неверный номер: %d. Доступны от 1 до %d.", num, len(clients)))
	}

	target := clients[num-1]
	if err := RemovePeer(*srv, target.ClientID); err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}

	return b.showMainMenuWithHeader(s, c.Bot(), uid, fmt.Sprintf("✅ Ключ #%d (%s) удалён с сервера %s", num, target.UserData.ClientName, srv.Name))
}

func (b *Bot) handleRenameSelectNumber(c tele.Context, s *UserSession, input string) error {
	num, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return b.showError(s, c.Bot(), "❌ Введите номер ключа (число).")
	}

	uid := c.Sender().ID
	srv, err2 := b.resolveServer(uid)
	if err2 != nil {
		return b.showError(s, c.Bot(), err2.Error())
	}

	clients, err := ListClients(*srv)
	if err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}
	if num < 1 || num > len(clients) {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Неверный номер: %d. Доступны от 1 до %d.", num, len(clients)))
	}

	target := clients[num-1]
	s.Screen = ScreenRenamePending
	s.PendingClientID = target.ClientID
	s.PendingClientName = target.UserData.ClientName
	s.PendingUserMsgIDs = []int{c.Message().ID}

	text := fmt.Sprintf("✏️ Переименование ключа #%d (%s)\nВведите новое имя:", num, target.UserData.ClientName)
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleRenameExecute(c tele.Context, s *UserSession, input string) error {
	newName := sanitizeName(input)
	if newName == "" {
		return b.showError(s, c.Bot(), "❌ Имя ключа не может быть пустым.")
	}

	// Collect second user message and delete both
	s.PendingUserMsgIDs = append(s.PendingUserMsgIDs, c.Message().ID)
	for _, msgID := range s.PendingUserMsgIDs {
		_ = c.Bot().Delete(&tele.Message{ID: msgID, Chat: &tele.Chat{ID: s.ChatID}})
	}
	s.PendingUserMsgIDs = nil

	uid := c.Sender().ID
	srv, err := b.resolveServer(uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	_ = b.editOrSend(s, c.Bot(), "⏳ Переименовываю...", nil)

	if err := RenamePeer(*srv, s.PendingClientID, newName); err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}

	return b.showMainMenuWithHeader(s, c.Bot(), uid, fmt.Sprintf("✅ Ключ \"%s\" переименован в \"%s\"", s.PendingClientName, newName))
}

func (b *Bot) handleServerRenameExecute(c tele.Context, s *UserSession, input string) error {
	newName := sanitizeName(input)
	if newName == "" {
		return b.showError(s, c.Bot(), "❌ Имя сервера не может быть пустым.")
	}

	if err := b.cfg.RenameServer(s.PendingServerIdx, newName); err != nil {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Ошибка переименования: %v", err))
	}

	uid := c.Sender().ID
	s.Screen = ScreenServerList
	return b.showServerList(s, c.Bot(), uid)
}

// sanitizeFileName creates a safe .conf filename for AmneziaWG.
// WireGuard tunnel names allow only [a-zA-Z0-9_=+.-] and max 15 chars.
// Format: awg<cleaned_name>.conf
var reUnsafeFileName = regexp.MustCompile(`[^a-zA-Z0-9_=+.\-]`)

func sanitizeFileName(name string) string {
	clean := reUnsafeFileName.ReplaceAllString(name, "")
	if len(clean) > 12 { // "awg" (3) + name (12) = 15 max
		clean = clean[:12]
	}
	if clean == "" {
		return "amneziawg.conf"
	}
	return "awg" + clean + ".conf"
}

// --- Shared logic ---

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
		return nil, fmt.Errorf("У вас доступно %d серверов. Выберите сервер в меню.", len(indices))
	}

	cfg := b.cfg.Get()
	for _, idx := range indices {
		if idx == activeIdx {
			return &cfg.Servers[idx], nil
		}
	}

	return nil, fmt.Errorf("Выбранный сервер больше не доступен. Выберите другой в меню.")
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
			if err == nil && n >= 1 {
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

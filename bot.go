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
	ScreenAddServerIP                // waiting for server IP input
	ScreenAddServerLogin             // waiting for server login input
	ScreenAddServerPass              // waiting for server password input
	ScreenAddServerName              // waiting for server name input
	ScreenAdminList                  // admin list for a server
	ScreenAdminAdd                   // waiting for new admin UID input
	ScreenAdminEdit                  // editing a specific admin
	ScreenInstallConfirm             // "AWG not found. Install?"
	ScreenInstallPort                // waiting for port input
	ScreenInstallIPv6                // "Enable IPv6?"
	ScreenInstallProgress            // installation in progress
	ScreenVersionScan                // опрос версий AWG на серверах
	ScreenRandomPortPick             // выбор сервера для настройки «случайного порта»
	ScreenRandomPort                 // экран режима «случайный порт»
	ScreenRandomPortRange            // ввод диапазона портов
)

// UserSession tracks the current UI state for a user.
//
// Обработчики telebot для одного пользователя выполняются последовательно, но
// установка AWG работает в отдельной горутине минутами и всё это время читает и
// пишет ту же сессию. Поэтому поля, которые видят обе стороны (Screen, MessageID,
// ChatID и Pending*-результаты установки), закрыты mu; b.mu защищает только карту
// сессий и здесь не помогает.
type UserSession struct {
	mu                sync.Mutex
	Screen            Screen
	MessageID         int // ID of the "menu message" we keep editing
	ChatID            int64
	PendingClientID   string // pubKey for rename
	PendingClientName string // current name for rename
	PendingServerIdx  int    // server index for server rename
	PendingUserMsgIDs []int  // user message IDs to delete after rename
	Page              int    // current page for paginated lists (0-based)
	// Add-server flow
	PendingServerIP    string         // IP for new server
	PendingServerLogin string         // login for new server
	PendingServerPass  string         // password for new server
	PendingServerMode  string         // detected mode ("docker"/"native")
	PendingServerDir   string         // detected AWG config dir
	PendingServerIface string         // detected AWG interface name
	PendingServerVer   AWGVersionInfo // detected AWG version
	// Admin management
	PendingAdminServerIdx int   // server index for admin management
	PendingAdminUID       int64 // UID of selected admin for editing
	// Install AWG flow
	PendingInstallPort   int    // AWG listen port
	PendingInstallIPv6   bool   // enable IPv6 for VPN
	PendingIPv6Subnet    string // computed VPN IPv6 client subnet CIDR
	PendingIPv6IfaceAddr string // computed AWG interface IPv6 address
	PendingNetIface      string // detected network interface
	// Опрос версий AWG («🔄 Проверить версии AWG»): идёт в отдельной горутине,
	// минутами, и должен прерываться кнопкой.
	VerScanID     int  // номер текущего опроса; новый опрос отменяет предыдущий
	VerScanCancel bool // выставляется кнопкой «Прервать»
	// Режим «случайный порт»
	PendingRandomPortIdx int // индекс сервера, который настраивается
}

// startVerScan объявляет начало нового опроса версий и возвращает его номер.
func (s *UserSession) startVerScan() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VerScanID++
	s.VerScanCancel = false
	return s.VerScanID
}

func (s *UserSession) cancelVerScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.VerScanCancel = true
}

// verScanStopped — прерван ли опрос с номером id: кнопкой или тем, что
// пользователь успел запустить следующий.
func (s *UserSession) verScanStopped(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.VerScanCancel || s.VerScanID != id
}

func (s *UserSession) screen() Screen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Screen
}

func (s *UserSession) setScreen(v Screen) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Screen = v
}

func (s *UserSession) messageID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.MessageID
}

func (s *UserSession) setMessageID(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MessageID = v
}

func (s *UserSession) chatID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ChatID
}

func (s *UserSession) setChatID(v int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ChatID = v
}

// withLock выполняет f под мьютексом сессии — для групп полей, которые нужно
// прочитать или записать согласованно (результаты установки AWG).
func (s *UserSession) withLock(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
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
	btnServerVer    = tele.InlineButton{Unique: "svv"}
	btnVerScanStop  = tele.InlineButton{Unique: "svvs"}
	// Режим «случайный порт»
	btnRandomPort       = tele.InlineButton{Unique: "rp"}
	btnRandomPortSel    = tele.InlineButton{Unique: "rps"}
	btnRandomPortToggle = tele.InlineButton{Unique: "rpt"}
	btnRandomPortRange  = tele.InlineButton{Unique: "rpr"}
	btnRandomPortBack   = tele.InlineButton{Unique: "rpb"}
	btnPagePrev         = tele.InlineButton{Unique: "ppv"}
	btnPageNext         = tele.InlineButton{Unique: "pnx"}
	btnNoop             = tele.InlineButton{Unique: "noop"}
	// Add-server
	btnAddServer = tele.InlineButton{Unique: "asv"}
	// Admin management
	btnAdminList         = tele.InlineButton{Unique: "adl"}
	btnAdminSel          = tele.InlineButton{Unique: "ads"}
	btnAdminAdd          = tele.InlineButton{Unique: "ada"}
	btnAdminEdit         = tele.InlineButton{Unique: "ade"}
	btnAdminDelete       = tele.InlineButton{Unique: "add"}
	btnAdminToggleReport = tele.InlineButton{Unique: "adr"}
	btnAdminBack         = tele.InlineButton{Unique: "adb"}
	// Install AWG
	btnInstallAWG  = tele.InlineButton{Unique: "iaw"}
	btnPortDefault = tele.InlineButton{Unique: "pd"}
	btnIPv6Yes     = tele.InlineButton{Unique: "i6y"}
	btnIPv6No      = tele.InlineButton{Unique: "i6n"}
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

// rememberUser запоминает ник и имя пользователя при любом обращении к боту —
// в списках админов UID сам по себе ничего не говорит.
func (b *Bot) rememberUser(u *tele.User) {
	if u == nil || u.ID == 0 {
		return
	}
	if !b.state.SeeUser(u.ID, u.Username, fullName(u.FirstName, u.LastName)) {
		return // ничего не изменилось — не трогаем диск
	}
	if err := b.state.Save(); err != nil {
		log.Printf("Сохранение профиля пользователя %d: %v", u.ID, err)
	}
}

func fullName(first, last string) string {
	return strings.TrimSpace(strings.TrimSpace(first) + " " + strings.TrimSpace(last))
}

// userTag — «123456 (@nick, Иван)» для списков админов.
func (b *Bot) userTag(uid int64) string {
	if label := b.state.UserLabel(uid); label != "" {
		return fmt.Sprintf("%d (%s)", uid, label)
	}
	return strconv.FormatInt(uid, 10)
}

// userShortTag — «@nick» или имя, а если о человеке ничего не известно — UID.
// Для строки ключа в статусе, где место ограничено.
func (b *Bot) userShortTag(uid int64) string {
	if short := b.state.UserShort(uid); short != "" {
		return short
	}
	return strconv.FormatInt(uid, 10)
}

func (b *Bot) getSession(uid, chatID int64) *UserSession {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.sessions[uid]
	if !ok {
		s = &UserSession{ChatID: chatID}
		b.sessions[uid] = s
	}
	s.setChatID(chatID)
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
			b.rememberUser(c.Sender())
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
	b.bot.Handle(&btnServerVer, b.cbRefreshVersion)
	b.bot.Handle(&btnVerScanStop, b.cbStopVersionScan)
	b.bot.Handle(&btnRandomPort, b.cbRandomPort)
	b.bot.Handle(&btnRandomPortSel, b.cbRandomPortSelect)
	b.bot.Handle(&btnRandomPortToggle, b.cbRandomPortToggle)
	b.bot.Handle(&btnRandomPortRange, b.cbRandomPortRange)
	b.bot.Handle(&btnRandomPortBack, b.cbRandomPortBack)
	b.bot.Handle(&btnPagePrev, b.cbPagePrev)
	b.bot.Handle(&btnPageNext, b.cbPageNext)
	b.bot.Handle(&btnNoop, func(c tele.Context) error { return c.Respond() })
	// Add-server
	b.bot.Handle(&btnAddServer, b.cbAddServer)
	// Admin management
	b.bot.Handle(&btnAdminList, b.cbAdminList)
	b.bot.Handle(&btnAdminSel, b.cbAdminSel)
	b.bot.Handle(&btnAdminAdd, b.cbAdminAdd)
	b.bot.Handle(&btnAdminEdit, b.cbAdminEdit)
	b.bot.Handle(&btnAdminDelete, b.cbAdminDelete)
	b.bot.Handle(&btnAdminToggleReport, b.cbAdminToggleReport)
	b.bot.Handle(&btnAdminBack, b.cbAdminBack)
	// Install AWG
	b.bot.Handle(&btnInstallAWG, b.cbInstallAWG)
	b.bot.Handle(&btnPortDefault, b.cbPortDefault)
	b.bot.Handle(&btnIPv6Yes, b.cbIPv6Yes)
	b.bot.Handle(&btnIPv6No, b.cbIPv6No)

	_ = b.bot.SetCommands([]tele.Command{
		{Text: "start", Description: "Главное меню"},
		{Text: "cancel", Description: "Отменить текущую операцию"},
	})

	b.startReportScheduler()
	b.startProfileRefresher()

	log.Println("Бот запущен")
	b.bot.Start()
}

// editOrSend tries to edit the session's menu message; falls back to sending a new one.
func (b *Bot) editOrSend(s *UserSession, bot *tele.Bot, text string, markup *tele.ReplyMarkup) error {
	if s.messageID() != 0 {
		msg := &tele.Message{ID: s.messageID(), Chat: &tele.Chat{ID: s.chatID()}}
		var err error
		if markup != nil {
			_, err = bot.Edit(msg, text, markup)
		} else {
			_, err = bot.Edit(msg, text)
		}
		if err == nil || strings.Contains(err.Error(), "message is not modified") {
			return nil
		}
		log.Printf("Edit failed (msg %d): %v", s.messageID(), err)
	}

	var sent *tele.Message
	var err error
	if markup != nil {
		sent, err = bot.Send(&tele.Chat{ID: s.chatID()}, text, markup)
	} else {
		sent, err = bot.Send(&tele.Chat{ID: s.chatID()}, text)
	}
	if err != nil {
		return err
	}
	s.setMessageID(sent.ID)
	return nil
}

// syncMessageID updates session's MessageID from callback context.
func syncMessageID(s *UserSession, c tele.Context) {
	if cb := c.Callback(); cb != nil && cb.Message != nil {
		s.setMessageID(cb.Message.ID)
	}
}

// --- Screen renderers ---

func (b *Bot) showMainMenu(s *UserSession, bot *tele.Bot, uid int64) error {
	return b.showMainMenuWithHeader(s, bot, uid, "")
}

func (b *Bot) showMainMenuWithHeader(s *UserSession, bot *tele.Bot, uid int64, header string) error {
	s.setScreen(ScreenMain)

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
		{markup.Data("🖥 Сервер", btnServerList.Unique)},
	}
	markup.Inline(rows...)

	return b.editOrSend(s, bot, text, markup)
}

// showLoading updates only the inline keyboard, adding ⏳ to the pressed button.
func (b *Bot) showLoading(s *UserSession, bot *tele.Bot, uid int64, loadingBtn string) {
	if s.messageID() == 0 {
		return
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
		{markup.Data("🖥 Сервер", btnServerList.Unique)},
	}
	markup.Inline(rows...)

	msg := &tele.Message{ID: s.messageID(), Chat: &tele.Chat{ID: s.chatID()}}
	_, _ = bot.EditReplyMarkup(msg, markup)
}

// showStatusLoading shows hourglass on the Refresh button while data is loading.
func (b *Bot) showStatusLoading(s *UserSession, bot *tele.Bot) {
	if s.messageID() == 0 {
		return
	}
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{
		markup.Data("⏳ Обновить", btnRefresh.Unique),
		markup.Data("↩ Меню", btnMenu.Unique),
	})
	msg := &tele.Message{ID: s.messageID(), Chat: &tele.Chat{ID: s.chatID()}}
	_, _ = bot.EditReplyMarkup(msg, markup)
}

// paginateClients returns the slice of clients for the current page and fixes s.Page if out of bounds.
// reverseClients returns clients in reverse order (newest first) while preserving their IDs.
func reverseClients(clients []ClientEntry) []ClientEntry {
	n := len(clients)
	rev := make([]ClientEntry, n)
	for i, cl := range clients {
		rev[n-1-i] = cl
	}
	return rev
}

func paginateClients(clients []ClientEntry, s *UserSession) []ClientEntry {
	total := len(clients)
	if total == 0 {
		s.Page = 0
		return nil
	}
	// Show newest clients first
	clients = reverseClients(clients)
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

// clientByNumberOnPage находит клиента по отображённому номеру (ID) среди клиентов
// текущей страницы; возвращает nil, если такого номера на странице нет.
func clientByNumberOnPage(page []ClientEntry, num int) *ClientEntry {
	for i := range page {
		if page[i].ID == num {
			return &page[i]
		}
	}
	return nil
}

// invalidNumberMsg формирует сообщение об ошибке с диапазоном доступных номеров.
func invalidNumberMsg(page []ClientEntry, num int) string {
	if len(page) == 0 {
		return "❌ Список пуст."
	}
	lo, hi := page[0].ID, page[0].ID
	for _, cl := range page {
		if cl.ID < lo {
			lo = cl.ID
		}
		if cl.ID > hi {
			hi = cl.ID
		}
	}
	return fmt.Sprintf("❌ Неверный номер: %d. Доступны от %d до %d.", num, lo, hi)
}

func (b *Bot) showStatus(s *UserSession, bot *tele.Bot, srv ServerConfig, uid int64) error {
	s.setScreen(ScreenStatus)

	clients, err := b.listVisibleClients(srv, uid)
	if err != nil {
		return b.showError(s, bot, formatError(srv, "", err, ""))
	}
	super := isSuperAdmin(uid, srv)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📋 Сервер: %s (всего: %d)\n", srv.Name, len(clients)))
	sb.WriteString(serverInfoLine(srv) + "\n\n")

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
			line := fmt.Sprintf("#%d %s  %s%s  ↓%s ↑%s", cl.ID, cl.UserData.ClientName, icon, formatHandshake(handshake), rx, tx)
			// Ключ выдан в режиме «случайный порт» — показываем его порт: без
			// этого непонятно, почему у ключей разные Endpoint.
			if cl.UserData.ClientPort != 0 {
				line += fmt.Sprintf("  🔌%d", cl.UserData.ClientPort)
			}
			// Суперадмину показываем владельца ключа.
			if super {
				if cl.UserData.CreatorUID != 0 {
					line += "  👤" + b.userShortTag(cl.UserData.CreatorUID)
				} else {
					line += "  👤—"
				}
			}
			sb.WriteString(line + "\n")
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
	s.setScreen(ScreenNewPrompt)
	text := fmt.Sprintf("📝 Новый ключ на сервере %s\nВведите имя ключа:", srv.Name)

	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})

	return b.editOrSend(s, bot, text, markup)
}

func (b *Bot) showDeletePrompt(s *UserSession, bot *tele.Bot, srv ServerConfig, uid int64) error {
	s.setScreen(ScreenDeletePrompt)

	clients, err := b.listVisibleClients(srv, uid)
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

func (b *Bot) showRenamePrompt(s *UserSession, bot *tele.Bot, srv ServerConfig, uid int64) error {
	s.setScreen(ScreenRenamePrompt)

	clients, err := b.listVisibleClients(srv, uid)
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
	s.setScreen(ScreenServerList)

	indices := b.cfg.ServersForUser(uid)
	cfg := b.cfg.Get()

	activeIdx, hasActive := b.state.GetActiveServer(uid)

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row

	// CLAUDE.md: отказ, если у пользователя 0 доступных серверов, с указанием его
	// UID. Исключение — пустой config.yaml: иначе первый сервер добавить нечем.
	if len(indices) == 0 && len(cfg.Servers) > 0 {
		return b.showError(s, bot, fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d\n\nПопросите админа добавить вас.", uid))
	}

	if len(indices) == 0 {
		// Пустой конфиг — режим первоначальной настройки, есть только «Добавить».
	} else {
		for i, idx := range indices {
			srv := cfg.Servers[idx]
			text := fmt.Sprintf("%s (%s)%s", srv.Name, srv.IP, versionBadge(srv))
			if hasActive && idx == activeIdx {
				text += " ✅"
			}
			rows = append(rows, tele.Row{markup.Data(text, btnServerSel.Unique, strconv.Itoa(i+1))})
		}
	}

	rows = append(rows, tele.Row{markup.Data("➕ Добавить сервер", btnAddServer.Unique)})
	rows = append(rows, tele.Row{
		markup.Data("👥 Админы", btnAdminList.Unique),
		markup.Data("✏️ Переименовать", btnServerRename.Unique),
	})
	// Не «обновить версию»: так кнопка читается как апгрейд AWG на серверах.
	// Бот только опрашивает серверы и обновляет свой кэш.
	rows = append(rows, tele.Row{markup.Data("🔄 Проверить версии AWG", btnServerVer.Unique)})
	rows = append(rows, tele.Row{markup.Data("🎲 Случайный порт", btnRandomPort.Unique)})
	rows = append(rows, tele.Row{markup.Data("↩ Меню", btnMenu.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, "🖥 Управление серверами:", markup)
}

// serverInfoLine — строка «⚙️ Native · AWG 3.0 · awg0» для шапки статуса.
// Данные берутся из кэша в config.yaml, без SSH: на горячем пути детект не нужен.
func serverInfoLine(srv ServerConfig) string {
	parts := []string{modeLabel(srv.Mode)}
	if v := srv.ProtoVersion(); v != AWGVersionUnknown {
		parts = append(parts, v.String())
	}
	parts = append(parts, srv.IfaceName())
	return "⚙️ " + strings.Join(parts, " · ")
}

// versionBadge — короткий бейдж версии для подписи кнопки сервера.
func versionBadge(srv ServerConfig) string {
	if v := srv.ProtoVersion(); v != AWGVersionUnknown {
		return " · " + v.String()
	}
	return ""
}

func modeLabel(mode string) string {
	if mode == "native" {
		return "Native"
	}
	return "Docker"
}

// versionLabel — «AWG 3.1 (tools 3.1.20260812)» для экрана добавления сервера.
func versionLabel(info AWGVersionInfo) string {
	if info.Version == AWGVersionUnknown {
		return "не определена"
	}
	label := info.Version.String()
	switch {
	case info.FromConfig && info.ToolsRaw != "":
		// Инструменты назвались старее, чем набор параметров в конфиге. Так почти
		// везде: до июня 2026 `awg --version` печатал 1.0.20210914 при любой
		// поддерживаемой версии протокола.
		label += " (по конфигу; awg --version: " + info.ToolsRaw + ")"
	case info.FromConfig:
		label += " (по конфигу)"
	case info.ToolsRaw != "":
		label += " (tools " + info.ToolsRaw + ")"
	}
	return label
}

// versionScanHeader — шапка экрана опроса версий. Кнопка называется «Проверить
// версии», и текст обязан снимать главный страх: бот НИЧЕГО не ставит и не
// обновляет на серверах, только читает и кладёт результат в свой config.yaml.
const versionScanHeader = "🔄 Проверка версий AWG\n\n" +
	"Бот только читает данные с серверов — ничего на них не устанавливает, не обновляет и не перезапускает:\n" +
	"• awg --version и modinfo amneziawg — версии инструментов и модуля ядра\n" +
	"• конфиг интерфейса — набор параметров обфускации\n" +
	"• awg show interfaces — имя интерфейса\n\n" +
	"Меняется только кэш в config.yaml самого бота: awg_version, awg_tools_version, iface.\n\n"

// cbRefreshVersion перечитывает версию AWG со всех доступных пользователю
// серверов. Кнопка живёт на экране списка серверов, поэтому обходит весь список;
// нужна потому, что версия на сервере меняется независимо от бота (apt upgrade).
//
// Опрос идёт в отдельной горутине: обработчики telebot для одного пользователя
// выполняются последовательно, и внутри обработчика нажатие «⛔ Прервать» просто
// не было бы обработано до конца обхода.
func (b *Bot) cbRefreshVersion(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	indices := b.cfg.ServersForUser(uid)
	if len(indices) == 0 {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid))
	}

	s.setScreen(ScreenVersionScan)
	scanID := s.startVerScan()
	bot := c.Bot()

	go b.runVersionScan(s, bot, uid, indices, scanID)
	return nil
}

// cbStopVersionScan просит опрос остановиться. Само сообщение перерисует
// горутина опроса — она дойдёт до ближайшей проверки и покажет итог.
func (b *Bot) cbStopVersionScan(c tele.Context) error {
	_ = c.Respond(&tele.CallbackResponse{Text: "Прерываю..."})
	s := b.getSession(c.Sender().ID, c.Chat().ID)
	s.cancelVerScan()
	return nil
}

// verScanResult — строка итогового отчёта по одному серверу.
type verScanResult struct {
	Name string
	Line string
}

// runVersionScan обходит серверы по одному, обновляя сообщение прогресса.
func (b *Bot) runVersionScan(s *UserSession, bot *tele.Bot, uid int64, indices []int, scanID int) {
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("⛔ Прервать", btnVerScanStop.Unique)})

	var done []verScanResult
	stopped := false

	for i, idx := range indices {
		if s.verScanStopped(scanID) {
			stopped = true
			break
		}

		cfg := b.cfg.Get()
		if idx >= len(cfg.Servers) {
			continue // конфиг перечитали, и сервера уже нет
		}
		srv := cfg.Servers[idx]

		progress := fmt.Sprintf("%s⏳ %d из %d: %s (%s)", versionScanHeader, i+1, len(indices), srv.Name, srv.IP)
		if len(done) > 0 {
			progress += "\n\nГотово:\n" + resultLines(done)
		}
		_ = b.editOrSend(s, bot, progress, markup)

		info, err := detectAWGVersion(srv)
		if err != nil {
			log.Printf("детект версии AWG (%s): %v", srv.Name, err)
			done = append(done, verScanResult{srv.Name, fmt.Sprintf("⚠️ %s — не удалось опросить", srv.Name)})
			continue
		}
		iface := refreshedIface(srv)
		if err := b.cfg.SetAWGInfo(idx, info, iface); err != nil {
			log.Printf("сохранение версии AWG (%s): %v", srv.Name, err)
			done = append(done, verScanResult{srv.Name, fmt.Sprintf("⚠️ %s — не удалось сохранить в config.yaml", srv.Name)})
			continue
		}
		done = append(done, verScanResult{srv.Name, fmt.Sprintf("• %s — %s · %s\n   %s", srv.Name, info.Version, iface, versionSource(info))})
	}

	// Экран мог смениться, пока шёл опрос: пользователь ушёл в другое меню.
	if s.screen() != ScreenVersionScan {
		return
	}

	back := &tele.ReplyMarkup{}
	back.Inline(tele.Row{back.Data("↩ К серверам", btnServerList.Unique)})

	var text string
	switch {
	case stopped && len(done) == 0:
		text = "⛔ Проверка прервана. Ни один сервер опросить не успели."
	case stopped:
		text = fmt.Sprintf("⛔ Проверка прервана. Успели опросить %d из %d:\n\n%s", len(done), len(indices), resultLines(done))
	default:
		text = fmt.Sprintf("✅ Готово, опрошено серверов: %d\n\n%s\n\nСведения сохранены в config.yaml бота.", len(done), resultLines(done))
	}
	_ = b.editOrSend(s, bot, text, back)
}

// versionSource — откуда взялась цифра версии: из `awg --version` или из набора
// параметров конфига (инструменты почти везде называются 1.0.20210914).
func versionSource(info AWGVersionInfo) string {
	tools := info.ToolsRaw
	if tools == "" {
		tools = "нет ответа"
	}
	if info.FromConfig {
		return "определена по параметрам конфига; awg --version: " + tools
	}
	if info.KmodRaw != "" {
		return "tools " + tools + ", модуль ядра " + info.KmodRaw
	}
	return "tools " + tools
}

func resultLines(done []verScanResult) string {
	lines := make([]string, 0, len(done))
	for _, r := range done {
		lines = append(lines, r.Line)
	}
	return strings.Join(lines, "\n")
}

// --- Режим «случайный порт» ---

func (b *Bot) cbRandomPort(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	return b.showRandomPortPick(s, c.Bot(), uid)
}

func (b *Bot) showRandomPortPick(s *UserSession, bot *tele.Bot, uid int64) error {
	s.setScreen(ScreenRandomPortPick)

	indices := b.cfg.ServersForUser(uid)
	if len(indices) == 0 {
		return b.showError(s, bot, fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid))
	}
	cfg := b.cfg.Get()

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	for i, idx := range indices {
		srv := cfg.Servers[idx]
		state := "выкл"
		if srv.RandomPort {
			state = fmt.Sprintf("вкл, блоков: %d", len(srv.RandomPortBlocks))
		}
		rows = append(rows, tele.Row{markup.Data(fmt.Sprintf("%s — %s", srv.Name, state), btnRandomPortSel.Unique, strconv.Itoa(i+1))})
	}
	rows = append(rows, tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, "🎲 Случайный порт — выберите сервер:", markup)
}

func (b *Bot) cbRandomPortSelect(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	num, err := strconv.Atoi(strings.TrimSpace(c.Callback().Data))
	if err != nil {
		return b.showError(s, c.Bot(), "❌ Ошибка выбора сервера.")
	}
	indices := b.cfg.ServersForUser(uid)
	if num < 1 || num > len(indices) {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Укажите номер от 1 до %d.", len(indices)))
	}

	s.withLock(func() { s.PendingRandomPortIdx = indices[num-1] })
	return b.showRandomPort(s, c.Bot(), uid)
}

func (b *Bot) cbRandomPortBack(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)
	return b.showRandomPort(s, c.Bot(), uid)
}

// randomPortTargetServer — сервер, который сейчас настраивается, с проверкой
// прав на каждое действие: индекс живёт в сессии и переживает перезагрузку
// конфига, а его нулевое значение — валидный индекс первого сервера.
func (b *Bot) randomPortTargetServer(s *UserSession, uid int64) (int, ServerConfig, error) {
	idx := 0
	s.withLock(func() { idx = s.PendingRandomPortIdx })

	cfg := b.cfg.Get()
	if idx < 0 || idx >= len(cfg.Servers) {
		return 0, ServerConfig{}, fmt.Errorf("❌ Сервер не найден")
	}
	srv := cfg.Servers[idx]
	for _, allowed := range srv.AllowedUIDs {
		if allowed == uid {
			return idx, srv, nil
		}
	}
	return 0, ServerConfig{}, fmt.Errorf("❌ Нет доступа к этому серверу.\nВаш UID: %d", uid)
}

func (b *Bot) showRandomPort(s *UserSession, bot *tele.Bot, uid int64) error {
	s.setScreen(ScreenRandomPort)

	_, srv, err := b.randomPortTargetServer(s, uid)
	if err != nil {
		return b.showError(s, bot, err.Error())
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🎲 Случайный порт — %s\n\n", srv.Name))

	if srv.RandomPort {
		sb.WriteString("Состояние: ✅ включён\n")
		if len(srv.RandomPortBlocks) > 0 {
			sb.WriteString(fmt.Sprintf("Блоки портов (%d × %d): %s\n",
				len(srv.RandomPortBlocks), portBlockSize, strings.Join(srv.RandomPortBlocks, ", ")))
		}
		unitActive, chainOK, statusErr := RandomPortStatus(srv)
		switch {
		case statusErr != nil:
			sb.WriteString("На сервере: не удалось проверить (сервер недоступен?)\n")
		case unitActive && chainOK:
			sb.WriteString("На сервере: правила стоят, служба активна\n")
		case chainOK:
			sb.WriteString("На сервере: правила стоят, но служба неактивна — после перезагрузки они пропадут\n")
		default:
			sb.WriteString("На сервере: ⚠️ правил нет. Нажмите «Переприменить»\n")
		}
	} else {
		sb.WriteString("Состояние: выключен\n")
	}
	sb.WriteString(fmt.Sprintf("Пул для выбора блоков: %s\n", srv.PortRange()))

	sb.WriteString(fmt.Sprintf("\nЧто делает: бот выбирает %d случайных блоков по %d портов, "+
		"проверяет, что там никто не слушает, и пробрасывает их на AWG. "+
		"Каждый новый ключ получает свой случайный порт из этих блоков — "+
		"один и тот же порт у всех заметен для DPI.\n\n", portBlockCount, portBlockSize))
	sb.WriteString("Как устроено: правила DNAT в цепочке " + randomPortChain + " (nat/PREROUTING), " +
		"их ставит systemd-юнит " + randomPortUnitName + " — они переживают перезагрузку. " +
		"Порты, которые кто-то слушает (и сам AWG), из перехвата исключаются при каждом старте.\n\n")
	sb.WriteString("⚠️ Если перед сервером есть облачный фаервол (Oracle, AWS, Hetzner), " +
		"диапазон нужно открыть и там.\n")
	if srv.RandomPort {
		sb.WriteString("⚠️ При выключении режима ключи, выданные со случайным портом, перестанут подключаться.\n")
	}

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	if srv.RandomPort {
		rows = append(rows, tele.Row{
			markup.Data("⛔ Выключить", btnRandomPortToggle.Unique, "off"),
			markup.Data("🔁 Переприменить", btnRandomPortToggle.Unique, "on"),
		})
		rows = append(rows, tele.Row{markup.Data("🎲 Перевыбрать блоки", btnRandomPortToggle.Unique, "reroll")})
	} else {
		rows = append(rows, tele.Row{markup.Data("✅ Включить", btnRandomPortToggle.Unique, "on")})
	}
	rows = append(rows, tele.Row{markup.Data("✏️ Пул портов", btnRandomPortRange.Unique)})
	rows = append(rows, tele.Row{markup.Data("↩ Назад", btnRandomPort.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, bot, sb.String(), markup)
}

func (b *Bot) cbRandomPortToggle(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	idx, srv, err := b.randomPortTargetServer(s, uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	switch strings.TrimSpace(c.Callback().Data) {
	case "off":
		_ = b.editOrSend(s, c.Bot(), "⏳ Снимаю правила с сервера...", nil)
		if err := DisableRandomPort(srv); err != nil {
			return b.showError(s, c.Bot(), formatError(srv, "", err, ""))
		}
		if err := b.cfg.SetRandomPort(idx, false, "", nil); err != nil {
			return b.showError(s, c.Bot(), formatError(srv, "", err, ""))
		}
	case "reroll":
		// Перевыбор блоков: ключи, выданные на старых портах, перестанут работать.
		_ = b.editOrSend(s, c.Bot(), "⏳ Выбираю новые блоки портов...", nil)
		if err := b.applyRandomPort(idx, srv, nil); err != nil {
			return b.showError(s, c.Bot(), formatError(srv, "", err, ""))
		}
	default: // "on" — включение и переприменение
		_ = b.editOrSend(s, c.Bot(), "⏳ Ставлю правила на сервер...", nil)
		if err := b.applyRandomPort(idx, srv, parsePortBlocks(srv.RandomPortBlocks)); err != nil {
			return b.showError(s, c.Bot(), formatError(srv, "", err, ""))
		}
	}
	return b.showRandomPort(s, c.Bot(), uid)
}

// applyRandomPort ставит правила на сервер и сохраняет выбранные блоки.
// reuse — блоки, которые стоит сохранить, если они всё ещё свободны (иначе уже
// выданные ключи с их портами перестанут подключаться); nil — выбрать заново.
func (b *Bot) applyRandomPort(idx int, srv ServerConfig, reuse []portBlock) error {
	blocks, err := EnableRandomPort(srv, srv.PortRange(), reuse)
	if err != nil {
		return err
	}
	return b.cfg.SetRandomPort(idx, true, srv.PortRange(), blockSpecs(blocks))
}

func (b *Bot) cbRandomPortRange(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	_, srv, err := b.randomPortTargetServer(s, uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	s.setScreen(ScreenRandomPortRange)
	text := fmt.Sprintf("✏️ Пул портов для %s\n\nСейчас: %s\n\n"+
		"Введите новый в формате 20000-32767. Из пула бот нарежет %d свободных блоков по %d портов — "+
		"пробрасываются только они, а не весь пул.\n\n"+
		"По умолчанию пул заканчивается на 32767: дальше начинается эфемерный "+
		"диапазон ядра (исходящие соединения самого сервера), и хотя DNAT их не ломает, "+
		"новый UDP-сервис на таком порту попал бы под перехват.",
		srv.Name, srv.PortRange(), portBlockCount, portBlockSize)
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnRandomPortBack.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleRandomPortRange(c tele.Context, s *UserSession, input string) error {
	uid := c.Sender().ID
	idx, srv, err := b.randomPortTargetServer(s, uid)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	rangeSpec := strings.TrimSpace(input)
	if _, _, err := parsePortRange(rangeSpec); err != nil {
		return b.showError(s, c.Bot(), "❌ "+err.Error())
	}

	if err := b.cfg.SetRandomPort(idx, srv.RandomPort, rangeSpec, nil); err != nil {
		return b.showError(s, c.Bot(), formatError(srv, "", err, ""))
	}

	// Включённый режим надо переприменить: блоки нарезаются из пула, а старые
	// могли оказаться за его границами.
	if srv.RandomPort {
		_ = b.editOrSend(s, c.Bot(), "⏳ Применяю новый пул на сервере...", nil)
		srv.RandomPortRange = rangeSpec
		if err := b.applyRandomPort(idx, srv, parsePortBlocks(srv.RandomPortBlocks)); err != nil {
			return b.showError(s, c.Bot(), formatError(srv, "", err, ""))
		}
	}
	return b.showRandomPort(s, c.Bot(), uid)
}

// refreshedIface — имя интерфейса по факту. Обновляем его только если интерфейс
// реально поднят: пустой вывод (интерфейс выключен) не должен затирать iface,
// настроенный в config.yaml вручную.
func refreshedIface(srv ServerConfig) string {
	out, err := execAWG(srv, "awg show interfaces")
	if err != nil {
		return srv.IfaceName()
	}
	ifaces := strings.Fields(out)
	if len(ifaces) == 0 {
		return srv.IfaceName()
	}
	return pickIface(ifaces, srv.IfaceName())
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
	s.setMessageID(0) // force new message on /start
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
	return b.showStatus(s, c.Bot(), *srv, uid)
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
	return b.showStatus(s, c.Bot(), *srv, uid)
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
	return b.showDeletePrompt(s, c.Bot(), *srv, uid)
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
	return b.showRenamePrompt(s, c.Bot(), *srv, uid)
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
	switch s.screen() {
	case ScreenStatus:
		return b.showStatus(s, bot, *srv, uid)
	case ScreenDeletePrompt:
		return b.showDeletePrompt(s, bot, *srv, uid)
	case ScreenRenamePrompt:
		return b.showRenamePrompt(s, bot, *srv, uid)
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
	s.setScreen(ScreenServerRenamePrompt)

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

	s.setScreen(ScreenServerRenamePending)
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

	switch s.screen() {
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
	case ScreenAddServerIP:
		return b.handleAddServerIP(c, s, text)
	case ScreenAddServerLogin:
		return b.handleAddServerLogin(c, s, text)
	case ScreenAddServerPass:
		return b.handleAddServerPass(c, s, text)
	case ScreenAddServerName:
		return b.handleAddServerName(c, s, text)
	case ScreenAdminAdd:
		return b.handleAdminAdd(c, s, text)
	case ScreenInstallPort:
		return b.handleInstallPort(c, s, text)
	case ScreenRandomPortRange:
		return b.handleRandomPortRange(c, s, text)
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

	clientConf, vpnURI, err := AddPeer(*srv, name, uid)
	if err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}

	// Send album: .conf file + QR image
	awgPNG, awgErr := buildQRPng(clientConf, qrcode.High, awgIconData, "iPhone — AmneziaWG")
	if awgErr != nil {
		log.Printf("AmneziaWG QR generation failed: %v", awgErr)
	}

	confCaption := "📄 Конфигурация\n\n" +
		"Скачайте приложение:\n" +
		"  iPhone — apps.apple.com/app/amneziawg/id6478942365\n" +
		"  Android — play.google.com/store/apps/details?id=org.amnezia.vpn\n" +
		"  PC, Mac — github.com/amnezia-vpn/amnezia-client/releases\n\n" +
		"iPhone: AmneziaWG → «+» → добавьте .conf файл или отсканируйте QR.\n" +
		"Android: откройте .conf файл → «Открыть в AmneziaVPN»."

	confDoc := &tele.Document{
		File:     tele.FromReader(strings.NewReader(clientConf)),
		FileName: sanitizeFileName(srv.Name),
		Caption:  confCaption,
	}

	if awgPNG != nil {
		qrDoc := &tele.Document{
			File:     tele.FromReader(bytes.NewReader(awgPNG)),
			FileName: "qr_amneziawg.png",
		}
		if err := c.SendAlbum(tele.Album{confDoc, qrDoc}); err != nil {
			log.Printf("SendAlbum failed: %v", err)
		}
	} else {
		if err := c.Send(confDoc); err != nil {
			log.Printf("Send conf failed: %v", err)
		}
	}

	// Send AmneziaVPN key as text message
	if vpnURI == "" {
		log.Printf("vpnURI is empty, skipping AmneziaVPN key message")
	} else {
		vpnText := "📱 Ключ для AmneziaVPN\n\n" +
			"Скопируйте ключ (нажмите на него) → откройте AmneziaVPN → «+» → «Вставить ключ из буфера обмена».\n\n" +
			"<code>" + vpnURI + "</code>"
		_, err := c.Bot().Send(&tele.Chat{ID: c.Sender().ID}, vpnText, &tele.SendOptions{
			ParseMode:             tele.ModeHTML,
			DisableWebPagePreview: true,
		})
		if err != nil {
			log.Printf("AmneziaVPN key send failed: %v", err)
		}
	}

	// Show main menu with success header
	s.setMessageID(0) // force new message for menu
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

	clients, err := b.listVisibleClients(*srv, uid)
	if err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}

	// Номер ищем среди ключей, видимых пользователю на текущей странице — так
	// обычный админ не может удалить чужой ключ, подобрав номер.
	page := paginateClients(clients, s)
	target := clientByNumberOnPage(page, num)
	if target == nil {
		return b.showError(s, c.Bot(), invalidNumberMsg(page, num))
	}

	_ = b.editOrSend(s, c.Bot(), "⏳ Удаляю...", nil)

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

	clients, err := b.listVisibleClients(*srv, uid)
	if err != nil {
		return b.showError(s, c.Bot(), formatError(*srv, "", err, ""))
	}

	// Номер ищем среди видимых пользователю ключей на текущей странице.
	page := paginateClients(clients, s)
	target := clientByNumberOnPage(page, num)
	if target == nil {
		return b.showError(s, c.Bot(), invalidNumberMsg(page, num))
	}

	s.setScreen(ScreenRenamePending)
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
		_ = c.Bot().Delete(&tele.Message{ID: msgID, Chat: &tele.Chat{ID: s.chatID()}})
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
	s.setScreen(ScreenServerList)
	return b.showServerList(s, c.Bot(), uid)
}

// --- Add server handlers ---

func (b *Bot) cbAddServer(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	// Добавлять серверы вправе только тот, у кого уже есть доступ хоть к одному
	// (либо кто угодно, пока конфиг пуст — первоначальная настройка).
	if len(b.cfg.ServersForUser(uid)) == 0 && len(b.cfg.Get().Servers) > 0 {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d\n\nПопросите админа добавить вас.", uid))
	}

	s.setScreen(ScreenAddServerIP)
	s.PendingServerIP = ""
	s.PendingServerLogin = ""
	s.PendingServerPass = ""
	s.PendingServerMode = ""
	s.PendingServerDir = ""
	s.PendingServerIface = ""
	s.PendingServerVer = AWGVersionInfo{}
	// Поля install-визарда тоже сбрасываем: иначе ipv6_subnet, net_iface и порт
	// от предыдущей установки попадут в конфиг следующего добавленного сервера.
	s.PendingInstallPort = 0
	s.PendingInstallIPv6 = false
	s.PendingIPv6Subnet = ""
	s.PendingIPv6IfaceAddr = ""
	s.PendingNetIface = ""

	text := "🖥 Новый сервер\nВведите IP-адрес:"
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleAddServerIP(c tele.Context, s *UserSession, input string) error {
	ip := strings.TrimSpace(input)
	if ip == "" {
		return b.showError(s, c.Bot(), "❌ IP-адрес не может быть пустым.")
	}

	s.PendingServerIP = ip
	s.setScreen(ScreenAddServerLogin)

	text := fmt.Sprintf("🖥 Новый сервер: %s\nВведите логин (SSH):", ip)
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleAddServerLogin(c tele.Context, s *UserSession, input string) error {
	login := strings.TrimSpace(input)
	if login == "" {
		return b.showError(s, c.Bot(), "❌ Логин не может быть пустым.")
	}

	s.PendingServerLogin = login
	s.setScreen(ScreenAddServerPass)

	text := fmt.Sprintf("🖥 Новый сервер: %s@%s\nВведите пароль (SSH):", login, s.PendingServerIP)
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleAddServerPass(c tele.Context, s *UserSession, input string) error {
	pass := strings.TrimSpace(input)
	if pass == "" {
		return b.showError(s, c.Bot(), "❌ Пароль не может быть пустым.")
	}

	s.PendingServerPass = pass

	// Delete the password message for security
	_ = c.Bot().Delete(c.Message())

	_ = b.editOrSend(s, c.Bot(), "⏳ Проверяю подключение...", nil)

	// First check SSH connectivity
	tmpSrv := ServerConfig{IP: s.PendingServerIP, Login: s.PendingServerLogin, Pass: pass}
	if _, sshErr := SSHRun(tmpSrv, "echo ok"); sshErr != nil {
		markup := &tele.ReplyMarkup{}
		markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
		return b.editOrSend(s, c.Bot(), fmt.Sprintf("❌ SSH подключение не удалось: %v", sshErr), markup)
	}

	det, err := detectAWGMode(s.PendingServerIP, s.PendingServerLogin, pass)
	if err != nil {
		// SSH works but AWG not found — offer installation
		s.setScreen(ScreenInstallConfirm)
		markup := &tele.ReplyMarkup{}
		markup.Inline(
			tele.Row{markup.Data("📦 Установить AWG", btnInstallAWG.Unique)},
			tele.Row{markup.Data("↩ Назад", btnServerList.Unique)},
		)
		text := fmt.Sprintf("⚠️ AWG не обнаружен на сервере %s\nХотите установить AmneziaWG?", s.PendingServerIP)
		return b.editOrSend(s, c.Bot(), text, markup)
	}

	s.PendingServerMode = det.Mode
	s.PendingServerDir = det.ConfDir
	s.PendingServerIface = det.Iface
	s.PendingServerVer = det.Version
	s.setScreen(ScreenAddServerName)

	text := fmt.Sprintf("✅ Подключение успешно!\nРежим: %s\nВерсия: %s\nИнтерфейс: %s\nПуть: %s\n\nВведите имя сервера:",
		modeLabel(det.Mode), versionLabel(det.Version), det.Iface, det.ConfDir)
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleAddServerName(c tele.Context, s *UserSession, input string) error {
	name := sanitizeName(input)
	if name == "" {
		return b.showError(s, c.Bot(), "❌ Имя сервера не может быть пустым.")
	}

	uid := c.Sender().ID
	// Читаем результаты детекта/установки согласованно: их пишет горутина установки.
	var newSrv ServerConfig
	s.withLock(func() {
		newSrv = ServerConfig{
			Name:        name,
			IP:          s.PendingServerIP,
			Login:       s.PendingServerLogin,
			Pass:        s.PendingServerPass,
			AllowedUIDs: []int64{uid},
			Mode:        s.PendingServerMode,
			AWGConfDir:  s.PendingServerDir,
			Port:        s.PendingInstallPort,
			NetIface:    s.PendingNetIface,
			AWGVersion:  int(s.PendingServerVer.Version),
			AWGToolsVer: s.PendingServerVer.ToolsRaw,
		}
		// Дефолтное имя интерфейса в YAML не пишем — его подставит IfaceName().
		if s.PendingServerIface != defaultIfaceName {
			newSrv.Iface = s.PendingServerIface
		}
		if s.PendingInstallIPv6 && s.PendingIPv6Subnet != "" {
			newSrv.IPv6Subnet = s.PendingIPv6Subnet
			if s.PendingIPv6IfaceAddr != "" && s.PendingIPv6IfaceAddr != s.PendingIPv6Subnet {
				newSrv.IPv6IfaceAddr = s.PendingIPv6IfaceAddr
			}
		}
	})

	// Don't store mode/dir for docker with default path (keep config clean)
	if newSrv.Mode == "docker" && newSrv.AWGConfDir == defaultDockerDir {
		newSrv.Mode = ""
		newSrv.AWGConfDir = ""
	}
	// Don't store default port
	if newSrv.Port == 51820 {
		newSrv.Port = 0
	}

	if err := b.cfg.AddServer(newSrv); err != nil {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Ошибка добавления: %v", err))
	}

	return b.showMainMenuWithHeader(s, c.Bot(), uid, fmt.Sprintf("✅ Сервер \"%s\" добавлен", name))
}

// --- Admin management handlers ---

func (b *Bot) cbAdminList(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	indices := b.cfg.ServersForUser(uid)
	if len(indices) == 0 {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid))
	}

	if len(indices) == 1 {
		s.PendingAdminServerIdx = indices[0]
		return b.showAdminList(s, c.Bot(), uid)
	}

	// Multiple servers — show selection
	cfg := b.cfg.Get()
	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	for i, idx := range indices {
		srv := cfg.Servers[idx]
		text := fmt.Sprintf("%s (%s)", srv.Name, srv.IP)
		rows = append(rows, tele.Row{markup.Data(text, btnAdminSel.Unique, strconv.Itoa(i+1))})
	}
	rows = append(rows, tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	markup.Inline(rows...)

	return b.editOrSend(s, c.Bot(), "👥 Выберите сервер для управления админами:", markup)
}

func (b *Bot) cbAdminSel(c tele.Context) error {
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
		return b.showError(s, c.Bot(), "❌ Неверный номер сервера.")
	}

	s.PendingAdminServerIdx = indices[num-1]
	return b.showAdminList(s, c.Bot(), uid)
}

func (b *Bot) showAdminList(s *UserSession, bot *tele.Bot, uid int64) error {
	s.setScreen(ScreenAdminList)

	cfg := b.cfg.Get()
	idx := s.PendingAdminServerIdx
	if idx < 0 || idx >= len(cfg.Servers) {
		return b.showError(s, bot, "❌ Сервер не найден.")
	}
	srv := cfg.Servers[idx]

	// Build report UID set for quick lookup
	reportSet := make(map[int64]bool)
	for _, u := range srv.ReportUIDs {
		reportSet[u] = true
	}

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row
	for _, adminUID := range srv.AllowedUIDs {
		label := b.userTag(adminUID)
		if adminUID == uid {
			label += " (вы)"
		}
		if reportSet[adminUID] {
			label += " 📊"
		}
		rows = append(rows, tele.Row{markup.Data(label, btnAdminEdit.Unique, fmt.Sprintf("%d", adminUID))})
	}
	rows = append(rows, tele.Row{markup.Data("➕ Добавить", btnAdminAdd.Unique)})
	rows = append(rows, tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
	markup.Inline(rows...)

	text := fmt.Sprintf("👥 Админы сервера: %s\n📊 = получает отчёты", srv.Name)
	return b.editOrSend(s, bot, text, markup)
}

func (b *Bot) cbAdminAdd(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	s.setScreen(ScreenAdminAdd)

	text := "Введите Telegram UID нового админа:"
	markup := &tele.ReplyMarkup{}
	markup.Inline(tele.Row{markup.Data("↩ Назад", btnAdminBack.Unique)})
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) handleAdminAdd(c tele.Context, s *UserSession, input string) error {
	newUID, err := strconv.ParseInt(strings.TrimSpace(input), 10, 64)
	if err != nil || newUID <= 0 {
		return b.showError(s, c.Bot(), "❌ Введите корректный числовой UID.")
	}

	uid := c.Sender().ID
	if _, err := b.adminTargetServer(uid, s.PendingAdminServerIdx); err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	if err := b.cfg.AddAllowedUID(s.PendingAdminServerIdx, newUID); err != nil {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Ошибка: %v", err))
	}

	return b.showAdminList(s, c.Bot(), uid)
}

// adminTargetServer проверяет, что вызывающий действительно имеет доступ к
// серверу с индексом idx. Индекс лежит в сессии и переживает перезагрузку
// config.yaml, удаление серверов и смену allowed_uids, а нулевое значение —
// валидный индекс первого сервера, поэтому право проверяется на каждое действие,
// а не только в момент выбора сервера в меню.
func (b *Bot) adminTargetServer(uid int64, idx int) (ServerConfig, error) {
	cfg := b.cfg.Get()
	if idx < 0 || idx >= len(cfg.Servers) {
		return ServerConfig{}, fmt.Errorf("❌ Сервер не найден.")
	}
	for _, allowed := range b.cfg.ServersForUser(uid) {
		if allowed == idx {
			return cfg.Servers[idx], nil
		}
	}
	return ServerConfig{}, fmt.Errorf("❌ У вас нет доступа к этому серверу.\nВаш UID: %d", uid)
}

// canManageReports — кто вправе менять report_uids, то есть список суперадминов.
// Без этой проверки любой обычный админ добавлял бы в отчёты себя и становился
// суперадмином, отключая модель видимости ключей, которая его же и ограничивает.
// Если суперадминов ещё нет, право у создателя сервера — первого UID в
// allowed_uids (его проставляет handleAddServerName).
func canManageReports(uid int64, srv ServerConfig) bool {
	if isSuperAdmin(uid, srv) {
		return true
	}
	return len(srv.ReportUIDs) == 0 && len(srv.AllowedUIDs) > 0 && srv.AllowedUIDs[0] == uid
}

func (b *Bot) cbAdminEdit(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	data := strings.TrimSpace(c.Callback().Data)
	adminUID, err := strconv.ParseInt(data, 10, 64)
	if err != nil {
		return b.showError(s, c.Bot(), "❌ Ошибка.")
	}

	s.PendingAdminUID = adminUID
	s.setScreen(ScreenAdminEdit)

	return b.showAdminEdit(s, c.Bot(), uid)
}

func (b *Bot) showAdminEdit(s *UserSession, bot *tele.Bot, uid int64) error {
	cfg := b.cfg.Get()
	idx := s.PendingAdminServerIdx
	if idx < 0 || idx >= len(cfg.Servers) {
		return b.showError(s, bot, "❌ Сервер не найден.")
	}
	srv := cfg.Servers[idx]

	// Check if admin is in report_uids
	inReport := false
	for _, u := range srv.ReportUIDs {
		if u == s.PendingAdminUID {
			inReport = true
			break
		}
	}

	markup := &tele.ReplyMarkup{}
	var rows []tele.Row

	rows = append(rows, tele.Row{markup.Data("🗑 Удалить админа", btnAdminDelete.Unique)})
	if inReport {
		rows = append(rows, tele.Row{markup.Data("📊 Убрать из отчётов", btnAdminToggleReport.Unique)})
	} else {
		rows = append(rows, tele.Row{markup.Data("📊 Добавить в отчёты", btnAdminToggleReport.Unique)})
	}
	rows = append(rows, tele.Row{markup.Data("↩ Назад", btnAdminBack.Unique)})
	markup.Inline(rows...)

	text := fmt.Sprintf("👤 Админ: %s\nСервер: %s", b.userTag(s.PendingAdminUID), srv.Name)
	if s.PendingAdminUID == uid {
		text += "\n(это вы)"
	}
	return b.editOrSend(s, bot, text, markup)
}

func (b *Bot) cbAdminDelete(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	srv, err := b.adminTargetServer(uid, s.PendingAdminServerIdx)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}

	// Последнего админа удалять нельзя: allowed_uids опустеет, и вернуть доступ
	// можно будет только правкой config.yaml на сервере вручную.
	if len(srv.AllowedUIDs) <= 1 {
		return b.showError(s, c.Bot(), "❌ Нельзя удалить последнего админа сервера.\nСначала добавьте другого.")
	}
	// Снять суперадмина вправе только суперадмин — иначе обычный админ удалял бы
	// того, кто его контролирует.
	if isSuperAdmin(s.PendingAdminUID, srv) && !isSuperAdmin(uid, srv) {
		return b.showError(s, c.Bot(), "❌ Удалять суперадмина может только суперадмин.")
	}

	if err := b.cfg.RemoveAllowedUID(s.PendingAdminServerIdx, s.PendingAdminUID); err != nil {
		return b.showError(s, c.Bot(), fmt.Sprintf("❌ Ошибка: %v", err))
	}

	return b.showAdminList(s, c.Bot(), uid)
}

func (b *Bot) cbAdminToggleReport(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	idx := s.PendingAdminServerIdx
	srv, err := b.adminTargetServer(uid, idx)
	if err != nil {
		return b.showError(s, c.Bot(), err.Error())
	}
	if !canManageReports(uid, srv) {
		return b.showError(s, c.Bot(), "❌ Управлять списком суперадминов (отчёты) может только суперадмин.")
	}

	// Check if already in report_uids
	inReport := false
	for _, u := range srv.ReportUIDs {
		if u == s.PendingAdminUID {
			inReport = true
			break
		}
	}

	if inReport {
		if err := b.cfg.RemoveReportUID(idx, s.PendingAdminUID); err != nil {
			return b.showError(s, c.Bot(), fmt.Sprintf("❌ Ошибка: %v", err))
		}
	} else {
		if err := b.cfg.AddReportUID(idx, s.PendingAdminUID); err != nil {
			return b.showError(s, c.Bot(), fmt.Sprintf("❌ Ошибка: %v", err))
		}
	}

	return b.showAdminList(s, c.Bot(), uid)
}

func (b *Bot) cbAdminBack(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	return b.showAdminList(s, c.Bot(), uid)
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

// isSuperAdmin сообщает, является ли пользователь суперадмином сервера.
// Суперадмин — это получатель отчётов (report_uids); он видит все ключи.
func isSuperAdmin(uid int64, srv ServerConfig) bool {
	for _, u := range srv.ReportUIDs {
		if u == uid {
			return true
		}
	}
	return false
}

// listVisibleClients возвращает ключи, видимые админу uid, с последовательной
// перенумерацией (ID = 1..N по порядку создания). Суперадмин видит все ключи;
// обычный админ — только созданные им и «ничьи» (CreatorUID == 0: старые ключи
// или созданные через приложение Amnezia). Перенумерация скрывает реальное
// количество ключей на сервере от обычного админа.
func (b *Bot) listVisibleClients(srv ServerConfig, uid int64) ([]ClientEntry, error) {
	all, err := ListClients(srv)
	if err != nil {
		return nil, err
	}
	return filterVisibleClients(all, uid, isSuperAdmin(uid, srv)), nil
}

// filterVisibleClients оставляет видимые админу ключи и перенумеровывает их 1..N.
func filterVisibleClients(all []ClientEntry, uid int64, super bool) []ClientEntry {
	var vis []ClientEntry
	for _, c := range all {
		if super || c.UserData.CreatorUID == 0 || c.UserData.CreatorUID == uid {
			vis = append(vis, c)
		}
	}
	for i := range vis {
		vis[i].ID = i + 1
	}
	return vis
}

func (b *Bot) resolveServer(uid int64) (*ServerConfig, error) {
	idx, err := b.resolveServerIdx(uid)
	if err != nil {
		return nil, err
	}
	cfg := b.cfg.Get()
	return &cfg.Servers[idx], nil
}

// resolveServerIdx — индекс активного сервера пользователя в config.Servers.
// Нужен там, где сервер требуется не только прочитать, но и обновить (SetAWGInfo).
func (b *Bot) resolveServerIdx(uid int64) (int, error) {
	indices := b.cfg.ServersForUser(uid)

	if len(indices) == 0 {
		return -1, fmt.Errorf("❌ У вас нет доступных серверов.\nВаш UID: %d", uid)
	}

	if len(indices) == 1 {
		return indices[0], nil
	}

	activeIdx, ok := b.state.GetActiveServer(uid)
	if !ok {
		return -1, fmt.Errorf("У вас доступно %d серверов. Выберите сервер в меню.", len(indices))
	}

	for _, idx := range indices {
		if idx == activeIdx {
			return idx, nil
		}
	}

	return -1, fmt.Errorf("Выбранный сервер больше не доступен. Выберите другой в меню.")
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

// --- Install AWG handlers ---

func (b *Bot) cbInstallAWG(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	s.setScreen(ScreenInstallPort)
	s.PendingInstallPort = 0
	s.PendingInstallIPv6 = false
	s.PendingIPv6Subnet = ""
	s.PendingIPv6IfaceAddr = ""
	s.PendingNetIface = ""

	text := "📦 Установка AmneziaWG\n\nВведите порт AWG (или нажмите кнопку):"
	markup := &tele.ReplyMarkup{}
	markup.Inline(
		tele.Row{markup.Data("51820 (по умолчанию)", btnPortDefault.Unique)},
		tele.Row{markup.Data("↩ Назад", btnServerList.Unique)},
	)
	return b.editOrSend(s, c.Bot(), text, markup)
}

func (b *Bot) cbPortDefault(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	s.PendingInstallPort = 51820
	return b.afterPortSelected(s, c.Bot(), uid)
}

func (b *Bot) handleInstallPort(c tele.Context, s *UserSession, input string) error {
	port, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || port < 1 || port > 65535 {
		return b.showError(s, c.Bot(), "❌ Введите корректный порт (1-65535).")
	}
	s.PendingInstallPort = port
	uid := c.Sender().ID
	return b.afterPortSelected(s, c.Bot(), uid)
}

func (b *Bot) afterPortSelected(s *UserSession, bot *tele.Bot, uid int64) error {
	// Check IPv6 on server
	_ = b.editOrSend(s, bot, "⏳ Проверяю IPv6 на сервере...", nil)

	tmpSrv := ServerConfig{IP: s.PendingServerIP, Login: s.PendingServerLogin, Pass: s.PendingServerPass}
	out, err := SSHRun(tmpSrv, "ip -6 addr show scope global")

	if err == nil && strings.Contains(out, "inet6") {
		// Parse IPv6 info for display
		ipv6Addr := ""
		prefix := 0
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "inet6 ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					addrCIDR := parts[1]
					if idx := strings.Index(addrCIDR, "/"); idx != -1 {
						ipv6Addr = addrCIDR[:idx]
						fmt.Sscanf(addrCIDR[idx+1:], "%d", &prefix)
					}
					break
				}
			}
		}

		if ipv6Addr != "" {
			ifaceAddr, clientSubnet, _ := calculateVPNv6Subnet(ipv6Addr, prefix)
			s.PendingIPv6IfaceAddr = ifaceAddr
			s.PendingIPv6Subnet = clientSubnet
			s.setScreen(ScreenInstallIPv6)

			text := fmt.Sprintf("🌐 IPv6 обнаружен: %s/%d\nVPN подсеть: %s\n\nВключить IPv6 для VPN?", ipv6Addr, prefix, clientSubnet)
			markup := &tele.ReplyMarkup{}
			markup.Inline(
				tele.Row{
					markup.Data("✅ Да", btnIPv6Yes.Unique),
					markup.Data("❌ Нет", btnIPv6No.Unique),
				},
				tele.Row{markup.Data("↩ Назад", btnServerList.Unique)},
			)
			return b.editOrSend(s, bot, text, markup)
		}
	}

	// No IPv6 — start installation directly
	s.PendingInstallIPv6 = false
	s.PendingIPv6Subnet = ""
	s.PendingIPv6IfaceAddr = ""
	b.startInstallation(s, bot, uid)
	return nil
}

func (b *Bot) cbIPv6Yes(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	s.PendingInstallIPv6 = true
	b.startInstallation(s, c.Bot(), uid)
	return nil
}

func (b *Bot) cbIPv6No(c tele.Context) error {
	_ = c.Respond()
	uid := c.Sender().ID
	s := b.getSession(uid, c.Chat().ID)
	syncMessageID(s, c)

	s.PendingInstallIPv6 = false
	s.PendingIPv6Subnet = ""
	s.PendingIPv6IfaceAddr = ""
	b.startInstallation(s, c.Bot(), uid)
	return nil
}

func (b *Bot) startInstallation(s *UserSession, bot *tele.Bot, uid int64) {
	s.setScreen(ScreenInstallProgress)
	_ = b.editOrSend(s, bot, "⏳ Установка AWG...\n\nШаг 1/13: Диагностика...", nil)

	// Снимаем параметры установки ДО запуска горутины: дальше она уже не должна
	// читать поля сессии напрямую — их в это же время правят обработчики кнопок.
	var (
		srv                                     ServerConfig
		installPort                             int
		installIPv6                             bool
		installIPv6IfaceAddr, installIPv6Subnet string
	)
	s.withLock(func() {
		srv = ServerConfig{
			Name:  s.PendingServerIP, // иначе SSH-ошибки печатаются с пустым именем
			IP:    s.PendingServerIP,
			Login: s.PendingServerLogin,
			Pass:  s.PendingServerPass,
		}
		installPort = s.PendingInstallPort
		installIPv6 = s.PendingInstallIPv6
		installIPv6IfaceAddr = s.PendingIPv6IfaceAddr
		installIPv6Subnet = s.PendingIPv6Subnet
	})

	go func() {
		progressFn := func(text string) {
			if s.screen() != ScreenInstallProgress {
				return
			}
			_ = b.editOrSend(s, bot, "⏳ Установка AWG...\n\n"+text, nil)
		}

		installLog, diag, err := InstallAWGNative(srv, installPort, installIPv6, installIPv6IfaceAddr, installIPv6Subnet, progressFn)
		if err != nil {
			if s.screen() != ScreenInstallProgress {
				return
			}
			progressFn("❌ Ошибка! Откатываю...")
			RollbackAWGInstall(srv, installLog)

			logText := installLog.String()

			// Send log as file if too long
			if len(logText) > 3500 {
				doc := &tele.Document{
					File:     tele.FromReader(strings.NewReader(logText)),
					FileName: "install_log.txt",
					Caption:  "Лог установки AWG. Перешлите разработчику для диагностики.",
				}
				_, _ = bot.Send(&tele.Chat{ID: s.chatID()}, doc)
			}

			errText := fmt.Sprintf("❌ Установка не удалась. Откат выполнен.\n\nОшибка: %s", installLog.LastError())
			if len(logText) <= 3500 {
				errText += "\n\n" + logText
			}
			markup := &tele.ReplyMarkup{}
			markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
			_ = b.editOrSend(s, bot, errText, markup)
			return
		}

		if s.screen() != ScreenInstallProgress {
			return
		}

		// Версию определяем ДО взятия мьютекса: это SSH-запрос на несколько секунд.
		nativeSrv := srv
		nativeSrv.Mode = "native"
		info, verErr := detectAWGVersion(nativeSrv)
		if verErr != nil {
			log.Printf("детект версии AWG после установки: %v", verErr)
		}

		// Success
		s.withLock(func() {
			s.PendingServerMode = "native"
			s.PendingServerDir = defaultNativeDir
			s.PendingServerIface = defaultIfaceName
			if verErr == nil {
				s.PendingServerVer = info
			}
			if diag != nil {
				s.PendingNetIface = diag.NetIface
			}
			s.Screen = ScreenAddServerName
		})

		ipv6Line := "нет"
		if installIPv6 {
			ipv6Line = installIPv6Subnet
		}
		text := fmt.Sprintf("✅ AWG установлен!\nПорт: %d\nIPv6: %s\n\nВведите имя сервера:", installPort, ipv6Line)
		markup := &tele.ReplyMarkup{}
		markup.Inline(tele.Row{markup.Data("↩ Назад", btnServerList.Unique)})
		_ = b.editOrSend(s, bot, text, markup)
	}()
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

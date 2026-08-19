package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const stateFilePath = "state.json"

// TrafficSnapshot stores per-peer byte counts at a point in time.
type TrafficSnapshot struct {
	Time  string           `json:"time"`  // RFC3339
	Peers map[string]int64 `json:"peers"` // pubKey -> rx+tx bytes
}

// UserInfo — как админ представлен в Telegram. Нужен, чтобы в списках вместо
// голого UID стояло понятное имя.
//
// Живёт в state.json, а не в config.yaml: config.yaml правится руками и
// перезаписывается ботом целиком, а это накопленные данные, а не настройка.
type UserInfo struct {
	Username  string `json:"username,omitempty"`   // без «@»
	Name      string `json:"name,omitempty"`       // FirstName + LastName
	FirstSeen string `json:"first_seen,omitempty"` // RFC3339
	UpdatedAt string `json:"updated_at,omitempty"` // RFC3339
}

// State persists user preferences across bot restarts.
type State struct {
	mu               sync.RWMutex
	ActiveServer     map[int64]int            `json:"active_server"`     // uid -> server index
	TrafficSnapshots map[int]*TrafficSnapshot `json:"traffic_snapshots"` // server index -> last snapshot
	Users            map[int64]*UserInfo      `json:"users"`             // uid -> профиль Telegram
}

// stateFile — форма state.json на диске: ключи map в JSON обязаны быть строками.
type stateFile struct {
	ActiveServer     map[string]int              `json:"active_server"`
	TrafficSnapshots map[string]*TrafficSnapshot `json:"traffic_snapshots"`
	Users            map[string]*UserInfo        `json:"users,omitempty"`
}

func LoadState() *State {
	s := &State{
		ActiveServer:     make(map[int64]int),
		TrafficSnapshots: make(map[int]*TrafficSnapshot),
		Users:            make(map[int64]*UserInfo),
	}

	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		return s
	}

	var raw stateFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return s
	}

	for k, v := range raw.ActiveServer {
		uid, err := strconv.ParseInt(k, 10, 64)
		if err == nil {
			s.ActiveServer[uid] = v
		}
	}

	for k, v := range raw.TrafficSnapshots {
		idx, err := strconv.Atoi(k)
		if err == nil {
			s.TrafficSnapshots[idx] = v
		}
	}

	for k, v := range raw.Users {
		uid, err := strconv.ParseInt(k, 10, 64)
		if err == nil && v != nil {
			s.Users[uid] = v
		}
	}

	return s
}

func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	raw := stateFile{
		ActiveServer:     make(map[string]int),
		TrafficSnapshots: make(map[string]*TrafficSnapshot),
		Users:            make(map[string]*UserInfo),
	}

	for k, v := range s.ActiveServer {
		raw.ActiveServer[strconv.FormatInt(k, 10)] = v
	}
	for k, v := range s.TrafficSnapshots {
		raw.TrafficSnapshots[strconv.Itoa(k)] = v
	}
	for k, v := range s.Users {
		raw.Users[strconv.FormatInt(k, 10)] = v
	}

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFilePath, data, 0644)
}

func (s *State) GetActiveServer(uid int64) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.ActiveServer[uid]
	return idx, ok
}

func (s *State) SetActiveServer(uid int64, idx int) {
	s.mu.Lock()
	s.ActiveServer[uid] = idx
	s.mu.Unlock()
}

func (s *State) GetTrafficSnapshot(serverIdx int) *TrafficSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TrafficSnapshots[serverIdx]
}

func (s *State) SetTrafficSnapshot(serverIdx int, snap *TrafficSnapshot) {
	s.mu.Lock()
	s.TrafficSnapshots[serverIdx] = snap
	s.mu.Unlock()
}

// SeeUser запоминает, как пользователь представлен в Telegram. Возвращает true,
// если что-то изменилось — только тогда есть смысл писать state.json (иначе
// диск дёргался бы на каждое нажатие кнопки).
//
// Пустые значения не затирают известные: getChat для пользователя, который
// скрыл имя, вернёт пустые поля, а старые данные лучше отсутствия данных.
func (s *State) SeeUser(uid int64, username, name string) bool {
	username = strings.TrimSpace(strings.TrimPrefix(username, "@"))
	name = strings.TrimSpace(name)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Format(time.RFC3339)
	u, ok := s.Users[uid]
	if !ok {
		if username == "" && name == "" {
			return false
		}
		s.Users[uid] = &UserInfo{Username: username, Name: name, FirstSeen: now, UpdatedAt: now}
		return true
	}

	changed := false
	if username != "" && username != u.Username {
		u.Username = username
		changed = true
	}
	if name != "" && name != u.Name {
		u.Name = name
		changed = true
	}
	if changed {
		u.UpdatedAt = now
	}
	return changed
}

// UserLabel — «@nick, Иван Петров» для списка админов; пусто, если о человеке
// ничего не известно.
func (s *State) UserLabel(uid int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.Users[uid]
	if !ok {
		return ""
	}
	var parts []string
	if u.Username != "" {
		parts = append(parts, "@"+u.Username)
	}
	if u.Name != "" {
		parts = append(parts, u.Name)
	}
	return strings.Join(parts, ", ")
}

// UserShort — самое короткое узнаваемое обозначение: ник, иначе имя, иначе
// пусто. Для тесных мест вроде строки ключа в статусе.
func (s *State) UserShort(uid int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.Users[uid]
	if !ok {
		return ""
	}
	if u.Username != "" {
		return "@" + u.Username
	}
	return u.Name
}

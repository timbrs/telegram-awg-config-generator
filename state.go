package main

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
)

const stateFilePath = "state.json"

// State persists user preferences across bot restarts.
type State struct {
	mu           sync.RWMutex
	ActiveServer map[int64]int `json:"active_server"` // uid -> server index
}

func LoadState() *State {
	s := &State{ActiveServer: make(map[int64]int)}

	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		return s
	}

	// JSON keys are strings, so we unmarshal into a temp map
	var raw struct {
		ActiveServer map[string]int `json:"active_server"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return s
	}

	for k, v := range raw.ActiveServer {
		uid, err := strconv.ParseInt(k, 10, 64)
		if err == nil {
			s.ActiveServer[uid] = v
		}
	}

	return s
}

func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Convert int64 keys to strings for JSON
	raw := struct {
		ActiveServer map[string]int `json:"active_server"`
	}{ActiveServer: make(map[string]int)}

	for k, v := range s.ActiveServer {
		raw.ActiveServer[strconv.FormatInt(k, 10)] = v
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

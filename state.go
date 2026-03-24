package main

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
)

const stateFilePath = "state.json"

// TrafficSnapshot stores per-peer byte counts at a point in time.
type TrafficSnapshot struct {
	Time  string            `json:"time"`            // RFC3339
	Peers map[string]int64  `json:"peers"`           // pubKey -> rx+tx bytes
}

// State persists user preferences across bot restarts.
type State struct {
	mu               sync.RWMutex
	ActiveServer     map[int64]int                `json:"active_server"`      // uid -> server index
	TrafficSnapshots map[int]*TrafficSnapshot     `json:"traffic_snapshots"`  // server index -> last snapshot
}

func LoadState() *State {
	s := &State{
		ActiveServer:     make(map[int64]int),
		TrafficSnapshots: make(map[int]*TrafficSnapshot),
	}

	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		return s
	}

	// JSON keys are strings, so we unmarshal into a temp map
	var raw struct {
		ActiveServer     map[string]int                    `json:"active_server"`
		TrafficSnapshots map[string]*TrafficSnapshot       `json:"traffic_snapshots"`
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

	for k, v := range raw.TrafficSnapshots {
		idx, err := strconv.Atoi(k)
		if err == nil {
			s.TrafficSnapshots[idx] = v
		}
	}

	return s
}

func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Convert int64/int keys to strings for JSON
	raw := struct {
		ActiveServer     map[string]int              `json:"active_server"`
		TrafficSnapshots map[string]*TrafficSnapshot `json:"traffic_snapshots"`
	}{
		ActiveServer:     make(map[string]int),
		TrafficSnapshots: make(map[string]*TrafficSnapshot),
	}

	for k, v := range s.ActiveServer {
		raw.ActiveServer[strconv.FormatInt(k, 10)] = v
	}
	for k, v := range s.TrafficSnapshots {
		raw.TrafficSnapshots[strconv.Itoa(k)] = v
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

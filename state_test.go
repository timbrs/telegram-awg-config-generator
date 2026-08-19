package main

import "testing"

func newTestState() *State {
	return &State{
		ActiveServer:     make(map[int64]int),
		TrafficSnapshots: make(map[int]*TrafficSnapshot),
		Users:            make(map[int64]*UserInfo),
	}
}

func TestSeeUser(t *testing.T) {
	s := newTestState()

	if !s.SeeUser(100, "timbrs", "Тимур") {
		t.Fatal("первое знакомство должно считаться изменением")
	}
	// Повтор тех же данных не должен дёргать диск.
	if s.SeeUser(100, "timbrs", "Тимур") {
		t.Error("повторное обращение без изменений не должно требовать сохранения")
	}
	if s.SeeUser(100, "@timbrs", "Тимур") {
		t.Error("«@» перед ником — то же самое имя")
	}

	if !s.SeeUser(100, "timbrs2", "Тимур") {
		t.Error("смена ника — изменение")
	}
	if got := s.UserLabel(100); got != "@timbrs2, Тимур" {
		t.Errorf("UserLabel = %q", got)
	}

	// Пустые значения не затирают известные: getChat может вернуть пустой ник.
	if s.SeeUser(100, "", "") {
		t.Error("пустые данные не должны считаться изменением")
	}
	if got := s.UserLabel(100); got != "@timbrs2, Тимур" {
		t.Errorf("пустые данные затёрли профиль: %q", got)
	}

	// О пользователе, про которого ничего не известно, запись не заводим.
	if s.SeeUser(200, "", "") {
		t.Error("пустое знакомство не должно создавать запись")
	}
	if _, ok := s.Users[200]; ok {
		t.Error("для пустого профиля создалась запись")
	}
}

func TestUserLabelAndShort(t *testing.T) {
	s := newTestState()

	if got := s.UserLabel(999); got != "" {
		t.Errorf("для незнакомого UID ожидалась пустая подпись, получено %q", got)
	}
	if got := s.UserShort(999); got != "" {
		t.Errorf("UserShort для незнакомого UID = %q", got)
	}

	s.SeeUser(1, "nick", "Иван Петров")
	if got := s.UserLabel(1); got != "@nick, Иван Петров" {
		t.Errorf("UserLabel = %q", got)
	}
	if got := s.UserShort(1); got != "@nick" {
		t.Errorf("UserShort должен предпочитать ник, получено %q", got)
	}

	// Без ника (в Telegram он не обязателен) остаётся имя.
	s.SeeUser(2, "", "Мария")
	if got := s.UserLabel(2); got != "Мария" {
		t.Errorf("UserLabel без ника = %q", got)
	}
	if got := s.UserShort(2); got != "Мария" {
		t.Errorf("UserShort без ника = %q", got)
	}
}

func TestFullName(t *testing.T) {
	tests := []struct{ first, last, want string }{
		{"Иван", "Петров", "Иван Петров"},
		{"Иван", "", "Иван"},
		{"", "Петров", "Петров"},
		{"", "", ""},
		{"  Иван  ", " Петров ", "Иван Петров"},
	}
	for _, tt := range tests {
		if got := fullName(tt.first, tt.last); got != tt.want {
			t.Errorf("fullName(%q, %q) = %q, ожидалось %q", tt.first, tt.last, got, tt.want)
		}
	}
}

package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// syncBuffer — потокобезопасная обёртка над bytes.Buffer. Нужна потому, что
// x/crypto/ssh копирует stdout и stderr в session.Stdout/session.Stderr из ДВУХ
// разных горутин. Если отдать им один и тот же bytes.Buffer, возникает data race
// (подтверждён -race): конкурентные Write периодически теряют весь stdout, из-за
// чего бот получал пустой вывод команд (пустой конфиг → пустой ключ → битый .conf).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func SSHRun(srv ServerConfig, cmd string) (string, error) {
	return SSHRunTimeout(srv, cmd, 10*time.Second)
}

// sshHost нормализует адрес хоста для net.JoinHostPort: снимает обрамляющие
// квадратные скобки у IPv6 (на случай, если в конфиге адрес записан как
// "[2a01:db8::1]"), чтобы избежать двойного оборачивания.
func sshHost(ip string) string {
	if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		return ip[1 : len(ip)-1]
	}
	return ip
}

func SSHRunTimeout(srv ServerConfig, cmd string, timeout time.Duration) (string, error) {
	config := &ssh.ClientConfig{
		User: srv.Login,
		Auth: []ssh.AuthMethod{
			ssh.Password(srv.Pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// net.JoinHostPort оборачивает IPv6-адрес в квадратные скобки ([2a01:db8::1]:22),
	// IPv4 и DNS-имена оставляет как есть (1.2.3.4:22).
	addr := net.JoinHostPort(sshHost(srv.IP), "22")
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("SSH (%s @ %s): %w", srv.Name, srv.IP, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH сессия (%s @ %s): %w", srv.Name, srv.IP, err)
	}
	defer session.Close()

	var buf syncBuffer
	session.Stdout = &buf
	session.Stderr = &buf

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("SSH команда (%s @ %s): %w\nКоманда: %s", srv.Name, srv.IP, err, cmd)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return buf.String(), fmt.Errorf("SSH команда (%s @ %s): %w\nКоманда: %s\nВывод: %s", srv.Name, srv.IP, err, cmd, buf.String())
		}
		return buf.String(), nil
	case <-time.After(timeout):
		_ = session.Close()
		return buf.String(), fmt.Errorf("SSH таймаут %s (%s @ %s)\nКоманда: %s\nВывод: %s", timeout, srv.Name, srv.IP, cmd, buf.String())
	}
}

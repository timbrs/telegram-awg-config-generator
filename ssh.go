package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// sshHostLog — адрес, на котором В ПОСЛЕДНИЙ РАЗ удалось подключиться к серверу.
//
// Нужен для UI: при заданном IPv6 бот может уйти на запасной адрес, и админ
// должен видеть, куда запрос ушёл на самом деле, а не то, что он выбрал.
var sshHostLog sync.Map // sshLogKey → sshHostRecord

type sshHostRecord struct {
	Host string
	At   time.Time
}

// sshLogKey — сервер опознаётся по имени вместе с основным адресом: имена в
// config.yaml не обязаны быть уникальными, а IP может смениться.
func sshLogKey(srv ServerConfig) string { return srv.Name + "|" + srv.IP }

func noteSSHHost(srv ServerConfig, host string) {
	sshHostLog.Store(sshLogKey(srv), sshHostRecord{Host: host, At: time.Now()})
}

// LastSSHHost — адрес последнего успешного подключения к серверу.
func LastSSHHost(srv ServerConfig) (sshHostRecord, bool) {
	v, ok := sshHostLog.Load(sshLogKey(srv))
	if !ok {
		return sshHostRecord{}, false
	}
	rec, ok := v.(sshHostRecord)
	return rec, ok
}

// sshDial подключается по адресам сервера в порядке предпочтения (SSHHosts).
// Второй адрес — фолбэк: IPv6 может не работать с машины, где живёт бот, и
// терять из-за настройки доступ к серверу нельзя. Возвращает адрес, на котором
// соединение удалось, — он идёт в сообщения об ошибках вместо srv.IP.
func sshDial(srv ServerConfig, config *ssh.ClientConfig) (*ssh.Client, string, error) {
	hosts := srv.SSHHosts()
	if len(hosts) == 0 {
		return nil, "", fmt.Errorf("SSH (%s): не задан адрес сервера", srv.Name)
	}

	var lastErr error
	for _, host := range hosts {
		// net.JoinHostPort оборачивает IPv6-адрес в квадратные скобки
		// ([2a01:db8::1]:22), IPv4 и DNS-имена оставляет как есть (1.2.3.4:22).
		addr := net.JoinHostPort(sshHost(host), "22")
		client, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			noteSSHHost(srv, host)
			return client, host, nil
		}
		lastErr = fmt.Errorf("SSH (%s @ %s): %w", srv.Name, host, err)
	}
	return nil, "", lastErr
}

func SSHRunTimeout(srv ServerConfig, cmd string, timeout time.Duration) (string, error) {
	auth, err := sshAuthMethods(srv)
	if err != nil {
		return "", err
	}
	config := &ssh.ClientConfig{
		User:            srv.Login,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, host, err := sshDial(srv, config)
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH сессия (%s @ %s): %w", srv.Name, host, err)
	}
	defer session.Close()

	var buf syncBuffer
	session.Stdout = &buf
	session.Stderr = &buf

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("SSH команда (%s @ %s): %w\nКоманда: %s", srv.Name, host, err, cmd)
	}

	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return buf.String(), fmt.Errorf("SSH команда (%s @ %s): %w\nКоманда: %s\nВывод: %s", srv.Name, host, err, cmd, buf.String())
		}
		return buf.String(), nil
	case <-time.After(timeout):
		_ = session.Close()
		return buf.String(), fmt.Errorf("SSH таймаут %s (%s @ %s)\nКоманда: %s\nВывод: %s", timeout, srv.Name, host, cmd, buf.String())
	}
}

// sshAuthMethods — способы аутентификации в порядке предпочтения.
//
// Ключ идёт первым: сервер с `PasswordAuthentication no` (germany-bvps) пароль
// не примет вовсе, а лишний метод в списке стоит одной неудачной попытки. Пароль
// остаётся вторым методом, чтобы серверы, заведённые до появления key_file,
// продолжали работать без правки config.yaml.
func sshAuthMethods(srv ServerConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if srv.KeyFile != "" {
		signer, err := loadSSHKey(srv.KeyFile, srv.KeyPass)
		if err != nil {
			return nil, fmt.Errorf("SSH-ключ (%s): %w", srv.Name, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if srv.Pass != "" {
		methods = append(methods, ssh.Password(srv.Pass))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("SSH (%s): не задан ни пароль (pass), ни ключ (key_file)", srv.Name)
	}
	return methods, nil
}

// loadSSHKey читает приватный ключ с диска. Путь может начинаться с `~`.
func loadSSHKey(path, passphrase string) (ssh.Signer, error) {
	expanded, err := expandHome(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(expanded)
	if err != nil {
		return nil, err
	}
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		// Отдельным сообщением: ключ под passphrase без key_pass — частая причина,
		// и стандартная ошибка про это молчит.
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return nil, fmt.Errorf("ключ зашифрован, укажите key_pass: %w", err)
		}
		return nil, err
	}
	return signer, nil
}

// expandHome раскрывает ведущий `~` в домашний каталог пользователя.
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeTestKey кладёт свежий ed25519-ключ в файл и возвращает путь.
func writeTestKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("сериализация ключа: %v", err)
	}
	if passphrase != "" {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
		if err != nil {
			t.Fatalf("шифрование ключа: %v", err)
		}
	}
	data := pem.EncodeToMemory(block)
	path := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("запись ключа: %v", err)
	}
	return path
}

func TestSSHAuthMethodsKeyFirst(t *testing.T) {
	key := writeTestKey(t, "")

	// Ключ и пароль вместе: ключ должен идти первым — сервер с
	// PasswordAuthentication no пароль не примет вовсе.
	methods, err := sshAuthMethods(ServerConfig{Name: "srv", KeyFile: key, Pass: "secret"})
	if err != nil {
		t.Fatalf("sshAuthMethods: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("ожидалось 2 метода (ключ + пароль), получено %d", len(methods))
	}

	// Только ключ — серверы вроде germany-bvps.
	methods, err = sshAuthMethods(ServerConfig{Name: "srv", KeyFile: key})
	if err != nil {
		t.Fatalf("sshAuthMethods (только ключ): %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("ожидался 1 метод, получено %d", len(methods))
	}

	// Только пароль — как было до появления key_file.
	methods, err = sshAuthMethods(ServerConfig{Name: "srv", Pass: "secret"})
	if err != nil {
		t.Fatalf("sshAuthMethods (только пароль): %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("ожидался 1 метод, получено %d", len(methods))
	}

	// Ни того, ни другого — внятная ошибка, а не молчаливый отказ в диалоге.
	if _, err := sshAuthMethods(ServerConfig{Name: "srv"}); err == nil {
		t.Fatal("ожидалась ошибка при пустых pass и key_file")
	}
}

func TestSSHAuthMethodsBadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken")
	if err := os.WriteFile(path, []byte("не ключ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sshAuthMethods(ServerConfig{Name: "srv", KeyFile: path}); err == nil {
		t.Fatal("битый ключ должен давать ошибку")
	}
	if _, err := sshAuthMethods(ServerConfig{Name: "srv", KeyFile: filepath.Join(t.TempDir(), "нет")}); err == nil {
		t.Fatal("отсутствующий файл должен давать ошибку")
	}
}

func TestSSHAuthMethodsPassphrase(t *testing.T) {
	key := writeTestKey(t, "swordfish")

	if _, err := sshAuthMethods(ServerConfig{Name: "srv", KeyFile: key}); err == nil {
		t.Fatal("зашифрованный ключ без key_pass должен давать ошибку")
	}
	if _, err := sshAuthMethods(ServerConfig{Name: "srv", KeyFile: key, KeyPass: "swordfish"}); err != nil {
		t.Fatalf("ключ с key_pass не принят: %v", err)
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("нет домашнего каталога")
	}
	got, err := expandHome("~/.ssh/id")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".ssh/id"); got != want {
		t.Errorf("expandHome: %q, ожидалось %q", got, want)
	}
	// Абсолютный путь не трогаем.
	abs := filepath.Join(home, "keys", "id")
	if got, _ := expandHome(abs); got != abs {
		t.Errorf("абсолютный путь изменён: %q", got)
	}
	// Тильда в середине — не путь к домашнему каталогу.
	if got, _ := expandHome("/tmp/~/id"); got != "/tmp/~/id" {
		t.Errorf("тильда в середине пути раскрыта: %q", got)
	}
}

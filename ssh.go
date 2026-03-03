package main

import (
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func SSHRun(srv ServerConfig, cmd string) (string, error) {
	config := &ssh.ClientConfig{
		User: srv.Login,
		Auth: []ssh.AuthMethod{
			ssh.Password(srv.Pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", srv.IP)
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

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return string(output), fmt.Errorf("SSH команда (%s @ %s): %w\nКоманда: %s\nВывод: %s", srv.Name, srv.IP, err, cmd, string(output))
	}

	return string(output), nil
}

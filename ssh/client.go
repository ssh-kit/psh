package ssh

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	// Host is the ssh server to connect to.
	Host string `yaml:"host"`

	// User is the user to authenticate as.
	User string `yaml:"user"`

	// Password is the password to use for authentication.
	Password string `yaml:"password,omitempty"`

	// IdentityFile is the path to the private key file to use for authentication.
	IdentityFile string `yaml:"identity_file,omitempty"`

	// LogLevel is the log level to use for logging
	LogLevel int8 `yaml:"log_level,omitempty"`

	// LogEncoding is the log output format
	LogEncoding string `yaml:"log_encoding"`

	// RetryMin is the minimum time to retry connecting to the ssh server
	RetryMin time.Duration `yaml:"retry_min,omitempty"`

	// RetryMax is the maximum time to retry connecting to the ssh server
	RetryMax time.Duration `yaml:"retry_max,omitempty"`

	// ServerAliveInterval is the interval to use for the ssh server's keepalive
	ServerAliveInterval time.Duration `yaml:"server_alive_interval"`

	// ServerAliveCountMax is the maximum number of keepalive packets to send
	ServerAliveCountMax uint32 `yaml:"server_alive_count_max"`

	// Rules is the list of rules to use for the ssh server
	Rules []Rule `yaml:"rules"`

	// Logger is the logger to use for logging
	Logger logr.Logger
}

type Rule struct {
	// Remote is the remote address to forward to
	Remote string `yaml:"remote,omitempty"`

	// Local is the local address to forward to
	Local string `yaml:"local,omitempty"`

	// Reverse is whether to reverse the direction of the connection
	Reverse bool `yaml:"reverse,omitempty"`
}

func (c *Client) Validate() error {
	if c.IdentityFile == "" && c.Password == "" {
		return fmt.Errorf("one of [password, identity_file] required")
	}

	if c.IdentityFile != "" {
		if strings.HasPrefix(c.IdentityFile, "~") {
			homePath, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			c.IdentityFile = strings.Replace(c.IdentityFile, "~", homePath, 1)
		}
	}

	if c.RetryMin <= 0 {
		c.RetryMin = time.Second
	}

	if c.RetryMax <= 0 {
		c.RetryMax = time.Minute
	}

	if c.ServerAliveInterval <= 0 {
		c.ServerAliveInterval = 0
	}

	if c.ServerAliveCountMax <= 1 {
		c.ServerAliveCountMax = 3
	}

	return nil
}

func (c *Client) keepAlive(ctx context.Context, conn ssh.Conn, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_, _, err := conn.SendRequest("keepalive@psh.dev", true, nil)
			if err != nil {
				c.Logger.Error(err, "keepalive")
				return
			}
			c.Logger.V(2).Info("keepalive",
				"host", c.Host,
				"user", c.User,
			)
		case <-ctx.Done():
			c.Logger.V(2).Info("keepalive",
				"status", "exit",
				"host", c.Host,
				"user", c.User,
			)
			return
		}
	}
}

func (c *Client) getCurrentTempDelay(tempDelay time.Duration) time.Duration {
	if tempDelay == 0 {
		tempDelay = c.RetryMin
	} else {
		tempDelay *= 2
	}
	if tempDelay > c.RetryMax {
		tempDelay = c.RetryMax
	}

	return tempDelay
}

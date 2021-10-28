package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
	"inet.af/tcpproxy"
)

const DefaultTime = time.Second * 2

type SSH struct {
	Config *Config
	Retry  time.Duration
	logger logr.Logger
}

type Config struct {
	Host                string        `yaml:"host"`
	User                string        `yaml:"user"`
	LogLevel            string        `yaml:"log_level,omitempty"`
	Password            string        `yaml:"password,omitempty"`
	IdentityFile        string        `yaml:"identity_file,omitempty"`
	RetryMin            time.Duration `yaml:"retry_min,omitempty"`
	RetryMax            time.Duration `yaml:"retry_max,omitempty"`
	ServerAliveInterval time.Duration `yaml:"server_alive_interval"`
	Rules               []Rules       `yaml:"rules"`
}

type Rules struct {
	Remote  string `yaml:"remote,omitempty"`
	Local   string `yaml:"local,omitempty"`
	Reverse bool   `yaml:"reverse,omitempty"`
}

func NewSSH(logger logr.Logger, retry time.Duration) *SSH {
	return &SSH{
		Config: &Config{},
		Retry:  retry,
		logger: logger,
	}
}

func (s *SSH) Run(ctx context.Context) error {
	c := s.Config

	if c.IdentityFile == "" && c.Password == "" {
		return fmt.Errorf("one of [password, identity_file] required")
	}

	var auth []ssh.AuthMethod
	if c.IdentityFile != "" {
		if strings.HasPrefix(c.IdentityFile, "~") {
			homePath, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			c.IdentityFile = strings.Replace(c.IdentityFile, "~", homePath, 1)
		}
		key, err := ioutil.ReadFile(c.IdentityFile)
		if err != nil {
			return err
		}
		singer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return err
		}

		auth = append(auth, ssh.PublicKeys(singer))
	}
	if c.Password != "" {
		auth = append(auth, ssh.Password(c.Password))
	}

	config := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 15,
	}

	for {
		conn, err := ssh.Dial("tcp", c.Host, config)
		if err != nil {
			s.logger.Error(err, "connect",
				"host", c.Host,
				"retry", s.Retry,
			)
			if s.Retry.Seconds() < s.Config.RetryMax.Seconds() {
				s.Retry = s.Retry * 2
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(s.Retry):
				continue
			}
		}

		s.logger.V(1).Info("connect",
			"host", c.Host,
		)

		connErr := make(chan error, 1)
		go func() {
			connErr <- conn.Wait()
		}()

		// run remote listen and proxy for each rule
		childCtx, childCancel := context.WithCancel(ctx)
		if c.ServerAliveInterval > 0 {
			go s.keepAlive(childCtx, conn, c.ServerAliveInterval)
		}
		go s.run(childCtx, conn)

		select {
		case <-ctx.Done():
			childCancel()
			conn.Close()
			return nil
		case <-connErr:
			s.logger.Error(conn.Wait(), "connect",
				"Host", c.Host,
				"retry", s.Retry,
			)
			childCancel()
			conn.Close()
			time.Sleep(s.Retry)
		}
	}
}

func (s *SSH) run(ctx context.Context, conn *ssh.Client) {
	for _, rule := range s.Config.Rules {
		if rule.Reverse {
			for {
				listen, err := conn.Listen("tcp", rule.Remote)
				if err != nil {
					s.logger.Error(err, "listen",
						"reverse", rule.Reverse,
						"remote", rule.Remote,
						"retry", s.Retry,
					)
					continue
				}

				s.logger.V(1).Info("listen",
					"reverse", rule.Reverse,
					"remote", rule.Remote,
				)

				// accept message and proxy
				go s.proxy(ctx, listen, rule)
				break
			}
		}
	}
}

func (s *SSH) proxy(ctx context.Context, l net.Listener, rule Rules) {
	dialProxy := tcpproxy.To(rule.Local)
	dialProxy.DialTimeout = time.Second * 15
	for {
		accept, err := l.Accept()
		if err != nil {
			s.logger.Error(err, "proxy",
				"remote", rule.Remote,
				"local", rule.Local,
				"retry", s.Retry,
			)

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.Retry):
				continue
			}
		}
		s.logger.V(2).Info("proxy",
			"status", "accept",
			"reverse", rule.Reverse,
			"remote", rule.Remote,
			"local", rule.Local,
		)

		dialProxy.HandleConn(accept)
		s.logger.V(2).Info("proxy",
			"status", "finish",
			"reverse", rule.Reverse,
			"remote", rule.Remote,
			"local", rule.Local,
		)
	}
}

func (s *SSH) keepAlive(ctx context.Context, conn ssh.Conn, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ok, _, err := conn.SendRequest("keepalive@psh.dev", true, nil)
			if err != nil {
				s.logger.Error(err, "keepalive")
				return
			}
			s.logger.V(2).Info("keepalive",
				"status", ok,
				"host", s.Config.Host,
			)
		case <-ctx.Done():
			s.logger.V(2).Info("keepalive",
				"status", "exited",
				"host", s.Config.Host,
			)
			return
		}
	}
}

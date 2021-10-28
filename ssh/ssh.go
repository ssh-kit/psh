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

const DefaultTime = time.Second * 5

type SSH struct {
	Config *Config
	logger logr.Logger
	retry  time.Duration
}

type Config struct {
	Host                string  `yaml:"host"`
	User                string  `yaml:"user"`
	Password            string  `yaml:"password,omitempty"`
	IdentityFile        string  `yaml:"identity_file,omitempty"`
	ServerAliveInterval string  `yaml:"server_alive_interval"`
	Rules               []Rules `yaml:"rules"`
}

type Rules struct {
	Remote  string `yaml:"remote,omitempty"`
	Local   string `yaml:"local,omitempty"`
	Reverse bool   `yaml:"reverse,omitempty"`
}

func NewSSH(logger logr.Logger, retry time.Duration) *SSH {
	return &SSH{
		Config: &Config{},
		logger: logger,
		retry:  retry,
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
		Timeout:         DefaultTime * 3,
	}

	for {
		conn, err := ssh.Dial("tcp", c.Host, config)
		if err != nil {
			s.logger.Error(err, "connect",
				"host", c.Host,
				"retry", s.retry,
			)
			if s.retry.Seconds() < 60 {
				s.retry = s.retry + 5
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(s.retry):
				continue
			}
		}

		s.logger.V(1).Info("connect",
			"host", c.Host,
		)

		// run remote listen and proxy for each rule
		childCtx, childCancel := context.WithCancel(ctx)
		closed := make(chan error, 1)
		go func() {
			closed <- conn.Wait()
			childCancel()
			conn.Close()
		}()

		go s.run(childCtx, conn)

		select {
		case <-ctx.Done():
			return conn.Close()
		case err = <-closed:
			s.logger.Error(err, "connect",
				"Host", c.Host,
				"retry", s.retry,
			)
			childCancel()
			time.Sleep(s.retry)
		}
	}
}

func (s *SSH) run(ctx context.Context, conn *ssh.Client) {
	for {
		closed := make(chan error, 1)
		for _, rule := range s.Config.Rules {
			if rule.Reverse {
				// open remote listen
				childClosed := make(chan error, 1)
				listen, err := conn.Listen("tcp", rule.Remote)
				if err != nil {
					s.logger.Error(err, "forward",
						"reverse", rule.Reverse,
						"remote", rule.Remote,
						"retry", s.retry,
					)

					closed <- err
					childClosed <- err
					listen.Close()
					break
				}

				s.logger.V(1).Info("forward",
					"reverse", rule.Reverse,
					"remote", rule.Remote,
				)

				// accept message and proxy
				childCtx, childCancel := context.WithCancel(ctx)
				go s.proxy(childCtx, listen, rule)
				go func() {
					<-childClosed
					childCancel()
				}()
			}
		}

		select {
		case <-closed:
			time.Sleep(s.retry)
		case <-ctx.Done():
			return
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
				"retry", s.retry,
			)

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.retry):
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

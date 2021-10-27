package ssh

import (
	"context"
	"net"
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
	for {
		config := &ssh.ClientConfig{
			User: c.User,
			Auth: []ssh.AuthMethod{
				ssh.Password(c.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		conn, err := ssh.Dial("tcp", c.Host, config)
		if err != nil {
			s.logger.Error(err, "connect",
				"host", c.Host,
				"retry", s.retry,
			)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(s.retry):
				continue
			}
		}

		// run remote listen and proxy for each rule

		closed := make(chan error, 1)
		go func() {
			closed <- conn.Wait()
			conn.Close()
		}()

		go s.run(ctx, conn)

		select {
		case <-ctx.Done():
			return conn.Close()
		case err = <-closed:
			s.logger.Error(err, "connect",
				"Host", c.Host,
				"retry", s.retry,
			)
			time.Sleep(s.retry)
		}
	}
}

func (s *SSH) run(ctx context.Context, conn *ssh.Client) {
	for {
		ch := make(chan error, 1)
		for _, rule := range s.Config.Rules {
			if rule.Reverse {
				// open remote listen
				l, err := conn.Listen("tcp", rule.Remote)
				if err != nil {
					s.logger.Error(err, "forward",
						"reverse", rule.Reverse,
						"remote", rule.Remote,
						"retry", s.retry,
					)

					ch <- err
					break
				}

				s.logger.V(1).Info("forward",
					"reverse", rule.Reverse,
					"remote", rule.Remote,
				)

				// accept message and proxy
				go s.proxy(l, rule)
			}
		}
		select {
		case <-ch:
			time.Sleep(s.retry)
		case <-ctx.Done():
			return
		}
	}
}

func (s *SSH) proxy(l net.Listener, rule Rules) {
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

			time.Sleep(s.retry)
			continue
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

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

func NewSSH(logger logr.Logger) *SSH {
	return &SSH{
		Config: &Config{},
		logger: logger,
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
				"retry", DefaultTime,
			)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(DefaultTime):
				continue
			}
		}

		// run remote listen and proxy for each rule

		closed := make(chan error, 1)
		go func() {
			closed <- conn.Wait()
		}()

		go s.run(conn)

		select {
		case <-ctx.Done():
			return conn.Close()
		case err = <-closed:
			s.logger.Error(err, "connect",
				"Host", c.Host,
				"retry", DefaultTime,
			)
			time.Sleep(DefaultTime)
		}
	}
}

func (s *SSH) run(conn *ssh.Client) {
	for _, rule := range s.Config.Rules {
		if rule.Reverse {
			// open remote listen
			l, err := conn.Listen("tcp", rule.Remote)
			if err != nil {
				s.logger.Error(err, "forward",
					"remote", rule.Remote,
				)
				time.Sleep(DefaultTime)
				continue
			}
			s.logger.V(1).Info("forward",
				"remote", rule.Remote,
			)

			// accept message and proxy
			go func(rule Rules, l net.Listener) {
				for {
					accept, err := l.Accept()
					if err != nil {
						s.logger.Error(err, "proxy",
							"remote", rule.Remote,
							"local", rule.Local,
							"retry", DefaultTime,
						)

						if conn.Wait().Error() != "" {
							return
						}

						time.Sleep(DefaultTime)
						continue
					}

					tcpproxy.To(rule.Local).HandleConn(accept)
					s.logger.V(2).Info("proxy",
						"remote", rule.Remote,
						"local", rule.Local,
					)
				}
			}(rule, l)
		}
	}
}

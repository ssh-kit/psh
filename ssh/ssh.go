package ssh

import (
	"context"
	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
	"inet.af/tcpproxy"
	"log"
	"net"
)

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
			log.Fatalf("%s unable to connect: %s", c.Host, err)
		}

		// run remote listen and proxy for each rule
		go s.run(conn)
		go func() {
			defer conn.Close()
			<-ctx.Done()
			log.Fatalln("interrupt!")
		}()

		if err := conn.Wait(); err != nil {
			s.logger.Error(err, "tcp listen",
				"Host", c.Host,
			)
			continue
		}
	}
}

func (s *SSH) run(conn *ssh.Client) {
	for _, rule := range s.Config.Rules {
		if rule.Reverse {
			// open remote listen
			l, err := conn.Listen("tcp", rule.Remote)
			if err != nil {
				s.logger.Error(err, "unable to register tcp forward")
				break
			}
			s.logger.V(0).Info("register tcp forward",
				"remote", rule.Remote,
			)

			// accept message and proxy
			go func(rule Rules, l net.Listener) {
				for {
					accept, err := l.Accept()
					if err != nil {
						s.logger.Error(err, "accept message",
							"remote", rule.Remote,
						)
						return
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

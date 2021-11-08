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

type SSH struct {
	Config *Config
	Retry  time.Duration
	logger logr.Logger
}

type Config struct {
	Host                string        `yaml:"host"`
	User                string        `yaml:"user"`
	LogLevel            int           `yaml:"log_level,omitempty"`
	Password            string        `yaml:"password,omitempty"`
	IdentityFile        string        `yaml:"identity_file,omitempty"`
	RetryMin            time.Duration `yaml:"retry_min,omitempty"`
	RetryMax            time.Duration `yaml:"retry_max,omitempty"`
	ServerAliveInterval time.Duration `yaml:"server_alive_interval"`
	ServerAliveCountMax uint32        `yaml:"server_alive_count_max"`
	Rules               []Rule        `yaml:"rules"`
}

type Rule struct {
	Remote  string `yaml:"remote,omitempty"`
	Local   string `yaml:"local,omitempty"`
	Reverse bool   `yaml:"reverse,omitempty"`
}

func NewSSH(logger logr.Logger) *SSH {
	return &SSH{
		Config: &Config{
			RetryMin: time.Second * 1,
			RetryMax: time.Second * 60,
		},
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
		Timeout:         time.Second * 30,
	}

	// how long to sleep on accept failure
	var tempDelay time.Duration
	for {
		conn, err := SSHDialTimeout("tcp", c.Host, config, c.ServerAliveInterval*time.Duration(c.ServerAliveCountMax))
		if err != nil {
			tempDelay = s.getCurrentTempDelay(tempDelay)
			s.logger.Error(err, "dial",
				"host", c.Host,
				"retry_in", tempDelay,
			)

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(tempDelay):
				continue
			}
		}
		startTime := time.Now()

		s.logger.V(1).Info("dial",
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
		case err := <-connErr:
			s.logger.Error(err, "connect",
				"Host", c.Host,
				"retry_in", tempDelay,
			)
			childCancel()
			conn.Close()

			// avoid too frequent reconnection
			endTime := time.Now()
			if endTime.Sub(startTime) < tempDelay {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(tempDelay - endTime.Sub(startTime)):
					tempDelay = s.getCurrentTempDelay(tempDelay)
					continue
				}
			} else {
				tempDelay = 0
			}
		}
	}
}

func (s *SSH) run(ctx context.Context, conn *ssh.Client) {
	var tempDelay time.Duration // how long to sleep on accept failure
	for _, rule := range s.Config.Rules {
		if rule.Reverse {
			for {
				listen, err := conn.Listen("tcp", rule.Remote)
				if err != nil {
					tempDelay = s.getCurrentTempDelay(tempDelay)

					s.logger.Error(err, "listen",
						"reverse", rule.Reverse,
						"remote", rule.Remote,
						"retry_in", tempDelay,
					)

					select {
					case <-ctx.Done():
						s.logger.V(2).Info("listen",
							"status", "canceled",
							"reverse", rule.Reverse,
							"remote", rule.Remote,
						)
						return
					case <-time.After(tempDelay):
						continue
					}
				}
				tempDelay = 0

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

func (s *SSH) proxy(ctx context.Context, l net.Listener, rule Rule) {
	dialProxy := tcpproxy.To(rule.Local)
	dialProxy.DialTimeout = time.Second * 15
	var tempDelay time.Duration
	for {
		accept, err := l.Accept()
		if err != nil {
			tempDelay = s.getCurrentTempDelay(tempDelay)

			select {
			case <-ctx.Done():
				s.logger.Error(err, "accept",
					"status", "exited",
					"remote", rule.Remote,
					"local", rule.Local,
					"reverse", rule.Reverse,
				)
				return
			case <-time.After(tempDelay):
				s.logger.Error(err, "accept",
					"remote", rule.Remote,
					"local", rule.Local,
					"reverse", rule.Reverse,
					"retry_in", tempDelay,
				)
				continue
			}
		}
		tempDelay = 0

		s.logger.V(2).Info("forward",
			"status", "start",
			"reverse", rule.Reverse,
			"remote", rule.Remote,
			"local", rule.Local,
		)
		go func() {
			dialProxy.HandleConn(accept)
			s.logger.V(2).Info("forward",
				"status", "end",
				"reverse", rule.Reverse,
				"remote", rule.Remote,
				"local", rule.Local,
			)
		}()
	}
}

func (s *SSH) keepAlive(ctx context.Context, conn ssh.Conn, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_, _, err := conn.SendRequest("keepalive@psh.dev", true, nil)
			if err != nil {
				s.logger.Error(err, "keepalive")
				return
			}
			s.logger.V(2).Info("keepalive",
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

func (s *SSH) getCurrentTempDelay(tempDelay time.Duration) time.Duration {
	if tempDelay == 0 {
		tempDelay = s.Config.RetryMin
	} else {
		tempDelay *= 2
	}
	if tempDelay > s.Config.RetryMax {
		tempDelay = s.Config.RetryMax
	}
	return tempDelay
}

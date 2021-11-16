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
	// Config is the ssh.ClientConfig to use when connecting to the SSH server.
	Config *Config

	// Retry specifies the time to retry connecting to the SSH server
	Retry time.Duration

	// Logger is the logger to use for logging
	Logger logr.Logger
}

type Config struct {
	// Host is the SSH server to connect to.
	Host string `yaml:"host"`

	// User is the user to authenticate as.
	User string `yaml:"user"`

	// LogLevel is the log level to use for logging
	LogLevel int8 `yaml:"log_level,omitempty"`

	// Password is the password to use for authentication.
	Password string `yaml:"password,omitempty"`

	// IdentityFile is the path to the private key file to use for authentication.
	IdentityFile string `yaml:"identity_file,omitempty"`

	// RetryMin is the minimum time to retry connecting to the SSH server
	RetryMin time.Duration `yaml:"retry_min,omitempty"`

	// RetryMax is the maximum time to retry connecting to the SSH server
	RetryMax time.Duration `yaml:"retry_max,omitempty"`

	// ServerAliveInterval is the interval to use for the SSH server's keepalive
	ServerAliveInterval time.Duration `yaml:"server_alive_interval"`

	// ServerAliveCountMax is the maximum number of keepalive packets to send
	ServerAliveCountMax uint32 `yaml:"server_alive_count_max"`

	// Rules is the list of rules to use for the SSH server
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	// Remote is the remote address to forward to
	Remote string `yaml:"remote,omitempty"`

	// Local is the local address to forward to
	Local string `yaml:"local,omitempty"`

	// Reverse is whether to reverse the direction of the connection
	Reverse bool `yaml:"reverse,omitempty"`
}

func NewSSH() *SSH {
	return &SSH{
		Config: &Config{
			ServerAliveInterval: time.Second * 30,
			ServerAliveCountMax: 3,
			RetryMin:            time.Second * 1,
			RetryMax:            time.Second * 60,
		},
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
	var tempConnDelay time.Duration
	for {
		conn, err := SSHDialTimeout("tcp", c.Host, config, c.ServerAliveInterval*time.Duration(c.ServerAliveCountMax))
		if err != nil {
			tempDelay = s.getCurrentTempDelay(tempDelay)
			s.Logger.Error(err, "dial",
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
		tempDelay = 0
		startTime := time.Now()

		s.Logger.V(1).Info("dial",
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
			s.Logger.Error(err, "connect",
				"Host", c.Host,
				"retry_in", tempConnDelay,
			)
			childCancel()
			conn.Close()

			// avoid too frequent reconnection
			durationTime := time.Since(startTime)
			tempConnDelay = s.getCurrentTempDelay(tempConnDelay)
			if durationTime < tempConnDelay {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(tempConnDelay - durationTime):
					continue
				}
			}
			if durationTime > s.Config.RetryMax {
				tempConnDelay = 0
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

					s.Logger.Error(err, "listen",
						"reverse", rule.Reverse,
						"remote", rule.Remote,
						"retry_in", tempDelay,
					)

					select {
					case <-ctx.Done():
						s.Logger.V(2).Info("listen",
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

				s.Logger.V(1).Info("listen",
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
				s.Logger.Error(err, "accept",
					"status", "exited",
					"remote", rule.Remote,
					"local", rule.Local,
					"reverse", rule.Reverse,
				)
				return
			case <-time.After(tempDelay):
				s.Logger.Error(err, "accept",
					"remote", rule.Remote,
					"local", rule.Local,
					"reverse", rule.Reverse,
					"retry_in", tempDelay,
				)
				continue
			}
		}
		tempDelay = 0

		s.Logger.V(2).Info("forward",
			"status", "start",
			"reverse", rule.Reverse,
			"remote", rule.Remote,
			"local", rule.Local,
		)
		go func() {
			dialProxy.HandleConn(accept)
			s.Logger.V(2).Info("forward",
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
				s.Logger.Error(err, "keepalive")
				return
			}
			s.Logger.V(2).Info("keepalive",
				"host", s.Config.Host,
			)
		case <-ctx.Done():
			s.Logger.V(2).Info("keepalive",
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

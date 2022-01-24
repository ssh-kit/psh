package ssh

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ssh-kit/psh/logger"

	"github.com/go-logr/logr"

	"golang.org/x/crypto/ssh"
	"inet.af/tcpproxy"
)

type Hosts struct {
	Clients []*Client `yaml:"client"`

	Logger logger.Logger
}

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

func NewHosts() *Hosts {
	return &Hosts{
		Clients: []*Client{},
	}
}

func (h *Hosts) Run(ctx context.Context) error {
	for _, s := range h.Clients {
		go func(s *Client) {
			l := h.Logger

			if s.LogLevel != 0 {
				l.LogLevel = s.LogLevel
			}
			if s.LogEncoding != "" {
				l.Encoding = s.LogEncoding
			}

			s.Logger = l.Build().WithName("ssh")

			if err := s.Run(ctx); err != nil {
				s.Logger.Error(err, "failed to run Client server", "host", s.Host)
				return
			}
		}(s)
	}
	return nil
}

func (s *Client) Validate() error {
	if s.IdentityFile == "" && s.Password == "" {
		return fmt.Errorf("one of [password, identity_file] required")
	}

	if s.IdentityFile != "" {
		if strings.HasPrefix(s.IdentityFile, "~") {
			homePath, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			s.IdentityFile = strings.Replace(s.IdentityFile, "~", homePath, 1)
		}
	}

	if s.RetryMin <= 0 {
		s.RetryMin = time.Second
	}

	if s.RetryMax <= 0 {
		s.RetryMax = time.Minute
	}

	if s.ServerAliveInterval <= 0 {
		s.ServerAliveInterval = 0
	}

	if s.ServerAliveCountMax <= 1 {
		s.ServerAliveCountMax = 3
	}

	return nil
}

func (s *Client) Run(ctx context.Context) error {
	if err := s.Validate(); err != nil {
		return err
	}

	var auth []ssh.AuthMethod
	if s.IdentityFile != "" {
		key, err := ioutil.ReadFile(s.IdentityFile)
		if err != nil {
			return err
		}
		singer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return err
		}
		auth = append(auth, ssh.PublicKeys(singer))
	}
	if s.Password != "" {
		auth = append(auth, ssh.Password(s.Password))
	}

	config := &ssh.ClientConfig{
		User:            s.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 30,
	}

	// how long to sleep on accept failure
	var tempDelay time.Duration
	var tempConnDelay time.Duration
	for {
		conn, err := SSHDialTimeout("tcp",
			s.Host,
			config,
			s.ServerAliveInterval*time.Duration(s.ServerAliveCountMax),
		)
		if err != nil {
			tempDelay = s.getCurrentTempDelay(tempDelay)
			s.Logger.Error(err, "dial",
				"host", s.Host,
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
			"host", s.Host,
		)

		connErr := make(chan error, 1)
		go func() {
			connErr <- conn.Wait()
		}()

		// run remote listen and proxy for each rule
		childCtx, childCancel := context.WithCancel(ctx)
		if s.ServerAliveInterval > 0 {
			go s.keepAlive(childCtx, conn, s.ServerAliveInterval)
		}

		go s.run(childCtx, conn)

		select {
		case <-ctx.Done():
			childCancel()
			conn.Close()
			return nil
		case err := <-connErr:
			s.Logger.Error(err, "connect",
				"Host", s.Host,
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
			if durationTime > s.RetryMax {
				tempConnDelay = 0
			}
		}
	}
}

func (s *Client) run(ctx context.Context, conn *ssh.Client) {
	var tempDelay time.Duration // how long to sleep on accept failure
	for _, rule := range s.Rules {
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

func (s *Client) proxy(ctx context.Context, l net.Listener, rule Rule) {
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

func (s *Client) keepAlive(ctx context.Context, conn ssh.Conn, interval time.Duration) {
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
				"host", s.Host,
			)
		case <-ctx.Done():
			s.Logger.V(2).Info("keepalive",
				"status", "exited",
				"host", s.Host,
			)
			return
		}
	}
}

func (s *Client) getCurrentTempDelay(tempDelay time.Duration) time.Duration {
	if tempDelay == 0 {
		tempDelay = s.RetryMin
	} else {
		tempDelay *= 2
	}
	if tempDelay > s.RetryMax {
		tempDelay = s.RetryMax
	}

	return tempDelay
}

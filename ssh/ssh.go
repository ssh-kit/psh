package ssh

import (
	"context"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"inet.af/tcpproxy"
)

func (c *Client) Dial(ctx context.Context) error {
	if err := c.Validate(); err != nil {
		return err
	}

	var auth []ssh.AuthMethod
	if c.IdentityFile != "" {
		key, err := os.ReadFile(c.IdentityFile)
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
		// establish connect with remote host
		conn, err := DialTimeout("tcp",
			c.Host,
			config,
			c.ServerAliveInterval*time.Duration(c.ServerAliveCountMax),
		)
		if err != nil {
			tempDelay = c.getCurrentTempDelay(tempDelay)
			c.Logger.Error(err, "dial",
				"status", "retry",
				"host", c.Host,
				"user", c.User,
				"retry_in", tempDelay,
			)

			select {
			case <-ctx.Done():
				c.Logger.Error(err, "dial",
					"status", "cancel",
					"host", c.Host,
					"user", c.User,
				)
				return nil
			case <-time.After(tempDelay):
				continue
			}
		}
		tempDelay = 0
		startTime := time.Now()

		c.Logger.V(1).Info("dial",
			"status", "ok",
			"host", c.Host,
			"user", c.User,
		)

		connErr := make(chan error, 1)
		go func() {
			connErr <- conn.Wait()
		}()

		// Listen remote listen and forward for each rule
		childCtx, childCancel := context.WithCancel(ctx)
		if c.ServerAliveInterval > 0 {
			go c.keepAlive(childCtx, conn, c.ServerAliveInterval)
		}

		go c.Listen(childCtx, conn)

		select {
		case <-ctx.Done():
			childCancel()
			conn.Close()
			return nil
		case err := <-connErr:
			c.Logger.Error(err, "connect",
				"status", "retry",
				"host", c.Host,
				"user", c.User,
				"retry_in", tempConnDelay,
			)
			childCancel()
			conn.Close()

			// avoid too frequent reconnection
			durationTime := time.Since(startTime)
			tempConnDelay = c.getCurrentTempDelay(tempConnDelay)
			if durationTime < tempConnDelay {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(tempConnDelay - durationTime):
					continue
				}
			}
			if durationTime > c.RetryMax {
				tempConnDelay = 0
			}
		}
	}
}

// Listen address which define in rules
func (c *Client) Listen(ctx context.Context, conn *ssh.Client) {
	for _, rule := range c.Rules {
		if rule.Reverse {
			go c.listenRemote(ctx, conn, rule)
		} else {
			go c.listenLocal(ctx, conn, rule)
		}
	}
}

func (c *Client) listenRemote(ctx context.Context, conn *ssh.Client, rule Rule) {
	var tempDelay time.Duration // how long to sleep on accept failure
ListenRemote:
	for {
		listener, err := conn.Listen("tcp", rule.Remote)
		if err != nil {
			tempDelay = c.getCurrentTempDelay(tempDelay)

			c.Logger.Error(err, "listen",
				"status", "retry",
				"host", c.Host,
				"user", c.User,
				"remote", rule.Remote,
				"reverse", rule.Reverse,
				"retry_in", tempDelay,
			)

			select {
			case <-ctx.Done():
				c.Logger.V(2).Info("listen",
					"status", "cancel",
					"host", c.Host,
					"user", c.User,
					"remote", rule.Remote,
					"reverse", rule.Reverse,
				)
				return
			case <-time.After(tempDelay):
				continue
			}
		}
		tempDelay = 0

		c.Logger.V(1).Info("listen",
			"status", "ok",
			"host", c.Host,
			"user", c.User,
			"remote", rule.Remote,
			"reverse", rule.Reverse,
		)

		// accept message and forward
		go c.forward(ctx, listener, rule.Local, rule, nil)

		select {
		case <-ctx.Done():
			c.Logger.V(1).Info("listen",
				"status", "cancel",
				"host", c.Host,
				"user", c.User,
				"remote", rule.Remote,
				"reverse", rule.Reverse,
			)
			listener.Close()
			break ListenRemote
		}
	}
}

func (c *Client) listenLocal(ctx context.Context, conn *ssh.Client, rule Rule) {
	var tempDelay time.Duration // how long to sleep on accept failure
ListenLocal:
	for {
		listener, err := net.Listen("tcp", rule.Local)
		if err != nil {
			tempDelay = c.getCurrentTempDelay(tempDelay)

			c.Logger.Error(err, "listen",
				"status", "retry",
				"host", c.Host,
				"user", c.User,
				"local", rule.Local,
				"reverse", rule.Reverse,
				"retry_in", tempDelay,
			)

			select {
			case <-ctx.Done():
				c.Logger.V(2).Info("listen",
					"status", "cancel",
					"host", c.Host,
					"user", c.User,
					"local", rule.Local,
					"reverse", rule.Reverse,
				)
				return
			case <-time.After(tempDelay):
				continue
			}
		}
		tempDelay = 0

		c.Logger.V(1).Info("listen",
			"status", "ok",
			"host", c.Host,
			"user", c.User,
			"local", rule.Local,
			"reverse", rule.Reverse,
		)

		// accept message and forward
		go c.forward(ctx, listener, rule.Remote, rule, func(ctx context.Context, network, address string) (net.Conn, error) {
			return conn.Dial(network, address)
		})

		select {
		case <-ctx.Done():
			c.Logger.V(1).Info("listen",
				"status", "cancel",
				"host", c.Host,
				"user", c.User,
				"local", rule.Local,
				"reverse", rule.Reverse,
			)
			listener.Close()
			break ListenLocal
		}
	}
}

func (c *Client) forward(ctx context.Context, source net.Listener, destination string, rule Rule, dialFunc func(ctx context.Context, network, address string) (net.Conn, error)) {
	dialProxy := tcpproxy.To(destination)
	dialProxy.DialTimeout = time.Second * 15
	if !rule.Reverse {
		dialProxy.DialContext = dialFunc
	}

	dialProxy.OnDialError = func(src net.Conn, dstDialErr error) {
		c.Logger.Error(dstDialErr, "forward",
			"status", "failure",
			"host", c.Host,
			"user", c.User,
			"remote", rule.Remote,
			"local", rule.Local,
			"reverse", rule.Reverse,
		)
	}

	var tempDelay time.Duration
	for {
		accept, err := source.Accept()
		if err != nil {
			tempDelay = c.getCurrentTempDelay(tempDelay)

			select {
			case <-ctx.Done():
				c.Logger.Error(err, "accept",
					"status", "cancel",
					"host", c.Host,
					"user", c.User,
					"remote", rule.Remote,
					"local", rule.Local,
					"reverse", rule.Reverse,
				)
				return
			case <-time.After(tempDelay):
				c.Logger.Error(err, "accept",
					"status", "retry",
					"host", c.Host,
					"user", c.User,
					"remote", rule.Remote,
					"local", rule.Local,
					"reverse", rule.Reverse,
					"retry_in", tempDelay,
				)
				continue
			}
		}
		tempDelay = 0

		c.Logger.V(2).Info("forward",
			"status", "start",
			"host", c.Host,
			"user", c.User,
			"remote", rule.Remote,
			"local", rule.Local,
			"reverse", rule.Reverse,
		)
		go func() {
			dialProxy.HandleConn(accept)
			c.Logger.V(2).Info("forward",
				"status", "end",
				"host", c.Host,
				"user", c.User,
				"remote", rule.Remote,
				"local", rule.Local,
				"reverse", rule.Reverse,
			)
		}()
	}
}

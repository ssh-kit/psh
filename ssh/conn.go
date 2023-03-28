package ssh

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Conn wraps a net.Conn, and sets a deadline for every read
// and write operation.
type Conn struct {
	net.Conn
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.ReadTimeout > 0 {
		err := c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
		if err != nil {
			return 0, err
		}
	}

	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.ReadTimeout > 0 {
		err := c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
		if err != nil {
			return 0, err
		}
	}

	return c.Conn.Write(b)
}

func DialTimeout(network, addr string, config *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}

	timeoutConn := &Conn{conn, timeout, timeout}
	c, chans, reqs, err := ssh.NewClientConn(timeoutConn, addr, config)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)

	return client, nil
}

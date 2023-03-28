package ssh

import (
	"context"

	"github.com/ssh-kit/psh/logger"
)

type Hosts struct {
	Clients []*Client `yaml:"client"`

	Logger logger.Logger
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

			if err := s.Dial(ctx); err != nil {
				s.Logger.Error(err, "dial", "host", s.Host)
				return
			}
		}(s)
	}
	return nil
}

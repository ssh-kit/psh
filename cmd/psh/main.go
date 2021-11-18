package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	"github.com/ssh-kit/psh/logger"
	"go.uber.org/zap/zapcore"

	"github.com/go-logr/logr"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffyaml"
	"github.com/ssh-kit/psh"
	"github.com/ssh-kit/psh/ssh"
	"gopkg.in/yaml.v2"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() { <-c; cancel() }()

	// Instantiate a new type to represent our application.
	m := NewMain()

	//Parse command line flags & load configuration.
	if err := m.ParseFlags(ctx, os.Args[1:]); err == flag.ErrHelp {
		os.Exit(1)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Execute program.
	if err := m.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Wait for CTRL-C.
	<-ctx.Done()
}

type Main struct {
	verbose int
	version bool
	config  string

	// Logger settings.
	encoding string
	Logger   logr.Logger

	hosts *ssh.Hosts
}

// NewMain returns a new instance of Main.
func NewMain() *Main {
	return &Main{
		hosts: ssh.NewHosts(),
	}
}

func (m *Main) ParseFlags(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("psh", flag.ExitOnError)
	{
		fs.BoolVar(&m.version, "version", false, "Show this program version")
		fs.IntVar(&m.verbose, "verbose", 1, "Show verbose logging")
		fs.StringVar(&m.encoding, "log-encoding", "console", "Log encoding format use \"json\" or \"console\"")
		fs.StringVar(&m.config, "config", "psh.yaml", "Config file path")
	}
	return ff.Parse(fs, args,
		ff.WithEnvVarPrefix("PSH"),
		ff.WithConfigFileParser(ffyaml.Parser),
	)
}

func (m *Main) Run(ctx context.Context) error {
	if m.version {
		fmt.Fprintf(os.Stdout, "Version: %s\n", psh.Version)
		os.Exit(0)
	}

	yamlFile, err := ioutil.ReadFile(m.config)
	if err != nil {
		return fmt.Errorf("read config file: %v", err)
	}
	err = yaml.Unmarshal(yamlFile, m.hosts)
	if err != nil {
		return fmt.Errorf("unmarshal config file: %v", err)
	}

	l := logger.NewLogger(int8(m.verbose), m.encoding, zapcore.ISO8601TimeEncoder)
	m.hosts.Logger = l

	m.Logger = l.Build()
	m.Logger.WithName("main").Info("started",
		"verbose", m.verbose,
		"config", m.config,
	)

	if err := m.hosts.Run(ctx); err != nil {
		return fmt.Errorf("run hosts: %v", err)
	}

	return nil
}

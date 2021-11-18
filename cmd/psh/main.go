package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"

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
	verbose   int
	version   bool
	configDir string

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
		fs.StringVar(&m.configDir, "config-dir", "./", "Dir of config files")
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

	l := logger.NewLogger(int8(m.verbose), m.encoding, zapcore.ISO8601TimeEncoder)
	m.hosts.Logger = l
	m.Logger = l.Build().WithName("main")
	m.Logger.Info("started",
		"verbose", m.verbose,
		"configDir", m.configDir,
	)

	fs, err := ioutil.ReadDir(m.configDir)
	if err != nil {
		return err
	}

	for _, f := range fs {
		if f.IsDir() {
			continue
		}

		suffix := filepath.Ext(f.Name())
		if suffix != ".yaml" && suffix != ".yml" {
			continue
		}

		file := filepath.Join(m.configDir, f.Name())
		yamlFile, err := ioutil.ReadFile(file)
		if err != nil {
			m.Logger.Error(err, "read file", "file", f.Name())
			continue
		}

		s := &ssh.SSH{}
		if err := yaml.Unmarshal(yamlFile, s); err != nil {
			m.Logger.Error(err, "unmarshal file", "file", f.Name())
			continue
		}

		m.Logger.V(1).Info("unmarshal",
			"host", s.Host,
			"file", file,
		)

		m.hosts.SSH = append(m.hosts.SSH, s)
	}

	if err := m.hosts.Run(ctx); err != nil {
		return fmt.Errorf("run hosts: %v", err)
	}

	return nil
}

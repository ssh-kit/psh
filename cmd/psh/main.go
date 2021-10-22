package main

import (
	"context"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/signal"

	"github.com/go-logr/logr"
	"github.com/iand/logfmtr"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffyaml"

	"github.com/ssh-kit/psh/ssh"
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

	Logger logr.Logger

	SSH *ssh.SSH
}

// NewMain returns a new instance of Main.
func NewMain() *Main {
	opts := logfmtr.DefaultOptions()
	opts.AddCaller = true
	logger := logfmtr.NewWithOptions(opts)
	return &Main{
		Logger: logger,
		SSH:    ssh.NewSSH(logger.WithName("ssh")),
	}
}

func (m *Main) ParseFlags(ctx context.Context, args []string) error {
	home, err := os.Getwd()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("psh", flag.ExitOnError)
	{
		fs.BoolVar(&m.version, "version", false, "Show this program version")
		fs.IntVar(&m.verbose, "verbose", 1, "Show verbose logging")
		fs.StringVar(&m.config, "config", fmt.Sprintf("%s/.psh/psh.yaml", home), "Config file path (Default ./.psh/psh.yaml)")
	}
	return ff.Parse(fs, args,
		ff.WithEnvVarPrefix("PSH"),
		ff.WithConfigFileParser(ffyaml.Parser),
	)
}

func (m *Main) Run(ctx context.Context) error {
	yamlFile, err := ioutil.ReadFile(m.config)
	err = yaml.Unmarshal(yamlFile, m.SSH.Config)
	if err != nil {
		fmt.Printf("%+v", &m.SSH.Config)
		fmt.Printf("%s", m.config)
		return fmt.Errorf("Unmarshal: %v\n", err)
	}

	if err = m.SSH.Run(ctx); err != nil {
		return err
	}

	return nil
}

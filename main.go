// Copyright (c) 2023, Benjamin Darnault <daniel.jantrambun@pm.me>
// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"
)

type dataFile struct {
	DeviceID       string
	AccessToken    string
	KDF            KDFType
	KDFIterations  int
	KDFMemory      int
	KDFParallelism int

	Sync syncData
}

var (
	globalData dataFile

	secrets secretCache

	apiURL string
	idtURL string
)

func init() { secrets.data = &globalData }

func newVaultK8sExportCommand() *vaultK8sExportCommand {
	vkc := &vaultK8sExportCommand{
		fs: flag.NewFlagSet("export", flag.ContinueOnError),
	}

	vkc.fs.StringVar(&vkc.email, "email", "", "vault user email")
	vkc.fs.StringVar(&vkc.password, "password", "", "vault user password")
	vkc.fs.StringVar(&vkc.URL, "url", "", "url of the vault server")
	vkc.fs.StringVar(&vkc.idtURL, "idturl", "", "url of the vault server for identity")
	vkc.fs.StringVar(&vkc.clientID, "clientId", "", "client ID for identity server")
	vkc.fs.StringVar(&vkc.clientSecret, "clientSecret", "", "client Secret for identity server")
	vkc.fs.StringVar(&vkc.collection, "collection", "", "collection")

	return vkc
}

type vaultK8sExportCommand struct {
	fs *flag.FlagSet

	email        string
	password     string
	clientSecret string
	clientID     string
	URL          string
	idtURL       string
	collection   string

	k8sSecrets []k8sSecret
}

type k8sSecretData struct {
	key   string `yaml:"key"`
	value string `yaml:"value"`
}
type k8sSecret struct {
	name string          `yaml:"name"`
	data []k8sSecretData `yaml:"data"`
}

func (g *vaultK8sExportCommand) Name() string {
	return g.fs.Name()
}

func (g *vaultK8sExportCommand) Init(args []string) error {
	return g.fs.Parse(args)
}

// readLine is similar to term.ReadPassword, but it doesn't use key codes.
func readLine(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	defer fmt.Fprintln(os.Stderr)

	var buf [1]byte
	var line []byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\n', '\r':
				return line, nil
			default:
				line = append(line, buf[0])
			}
		} else if err != nil {
			if err == io.EOF && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}

func (g *vaultK8sExportCommand) getClientSecret() error {
	if g.clientSecret != "" {
		return nil
	}
	if s := os.Getenv("CLIENT_SECRET"); s != "" {
		g.clientSecret = s
		return nil
	}
	clientSecret, err := passwordPrompt("Client Secret")
	if err != nil {
		return err
	}
	g.clientSecret = string(clientSecret[:])
	return nil
}

func (g *vaultK8sExportCommand) getPassword() error {
	if g.password != "" {
		return nil
	}
	if s := os.Getenv("PASSWORD"); s != "" {
		g.password = s
		return nil
	}
	password, err := passwordPrompt("Vault password")
	if err != nil {
		return err
	}
	g.password = string(password[:])
	return nil
}

func passwordPrompt(prompt string) ([]byte, error) {
	// TODO: Support cancellation with ^C. Currently not possible in any
	// simple way. Closing os.Stdin on cancel doesn't seem to do the trick
	// either. Simply doing an os.Exit keeps the terminal broken because of
	// ReadPassword.

	fd := int(os.Stdin.Fd())
	switch {
	case term.IsTerminal(fd):
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		password, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err == nil && len(password) == 0 {
			err = io.ErrUnexpectedEOF
		}
		return password, err
	case os.Getenv("FORCE_STDIN_PROMPTS") == "true":
		return readLine(prompt)
	default:
		return nil, fmt.Errorf("need a terminal to prompt for a password")
	}
}

func (g *vaultK8sExportCommand) Run() error {
	/*
		1. Get a JWT token from the vault server
		2. Get a list of all the secrets
		3. For each secret, get the secret
		4. Write the secret to a file
	*/
	err := g.getPassword()
	if err != nil {
		return err
	}
	err = g.getClientSecret()
	if err != nil {
		return err
	}
	secrets._email = g.email
	secrets._password = []byte(g.password)
	secrets._clientSecret = []byte(g.clientSecret)
	secrets._clientID = []byte(g.clientID)

	apiURL = g.URL
	idtURL = g.idtURL

	ctx := context.Background()
	if err := loginToVault(ctx, true); err != nil {
		return err
	}
	ctx = context.WithValue(ctx, authToken{}, globalData.AccessToken)
	if err := sync(ctx); err != nil {
		return err
	}
	slog.Debug(fmt.Sprint("Profile name", secrets.data.Sync.Profile.Name))
	currentNamespace := strings.Split(g.collection, "/")[1]

	slog.Debug(fmt.Sprint("namespace ", currentNamespace))

	collectionIDs, err := buildCollections(g.collection)
	if err != nil {
		slog.Error(fmt.Sprint("Error getting collections", err))
	}
	g.k8sSecrets, err = buildK8sSecrets(collectionIDs)
	if err != nil {
		fmt.Println("Error building k8s secrets", err)
	}

	err = setK8sSecrets(currentNamespace, g.k8sSecrets)
	if err != nil {
		slog.Error("Error setting k8s secrets", err)
	}

	return nil
}

type runner interface {
	Init([]string) error
	Run() error
	Name() string
}

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func root(args []string) error {
	if len(args) < 1 {
		return errors.New("You must pass a sub-command")
	}
	cmds := []runner{
		newVaultK8sExportCommand(),
	}

	subcommand := os.Args[1]
	for _, cmd := range cmds {
		if cmd.Name() == subcommand {
			cmd.Init(os.Args[2:])
			return cmd.Run()
		}
	}
	return fmt.Errorf("Unknown subcommand: %s", subcommand)

}
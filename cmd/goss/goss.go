package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aelsabbahy/goss"
	"github.com/aelsabbahy/goss/outputs"
	"github.com/aelsabbahy/goss/system"
	"github.com/aelsabbahy/goss/util"

	"github.com/fatih/color"
	"github.com/urfave/cli"
)

var version string

// converts a cli context into a goss Config
func newRuntimeConfigFromCLI(c *cli.Context) *util.Config {
	cfg := &util.Config{
		AllowInsecure:     c.Bool("insecure"),
		AnnounceToCLI:     true,
		CACert:            c.String("cacert"),
		Cache:             c.Duration("cache"),
		ClientCert:        c.String("cert"),
		ClientKey:         c.String("key"),
		Debug:             c.Bool("debug"),
		Endpoint:          c.String("endpoint"),
		FormatOptions:     c.StringSlice("format-options"),
		IgnoreList:        c.GlobalStringSlice("exclude-attr"),
		LastOutput:        c.String("last-output"),
		ListenAddress:     c.String("listen-addr"),
		MaxConcurrent:     c.Int("max-concurrent"),
		NoFollowRedirects: c.Bool("no-follow-redirects"),
		OutputFormat:      c.String("format"),
		PackageManager:    c.GlobalString("package"),
		Password:          c.String("password"),
		Proxy:             c.String("proxy"),
		RetryTimeout:      c.Duration("retry-timeout"),
		Server:            c.String("server"),
		Sleep:             c.Duration("sleep"),
		Spec:              c.GlobalString("gossfile"),
		Timeout:           c.Duration("timeout"),
		Username:          c.String("username"),
		Vars:              c.GlobalString("vars"),
		VarsInline:        c.GlobalString("vars-inline"),
	}

	if c.Bool("no-color") {
		util.WithNoColor()(cfg)
	}

	if c.Bool("color") {
		util.WithColor()(cfg)
	}

	return cfg
}

func timeoutFlag(value time.Duration) cli.DurationFlag {
	return cli.DurationFlag{
		Name:  "timeout",
		Value: value,
	}
}

func main() {
	startTime := time.Now()
	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Version = version
	app.Name = "goss"
	app.Usage = "Quick and Easy server validation"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "gossfile, g",
			Value:  "./goss.yaml",
			Usage:  "Goss file to read from / write to",
			EnvVar: "GOSS_FILE",
		},
		cli.StringFlag{
			Name:   "vars",
			Usage:  "json/yaml file containing variables for template",
			EnvVar: "GOSS_VARS",
		},
		cli.StringFlag{
			Name:   "vars-inline",
			Usage:  "json/yaml string containing variables for template (overwrites vars)",
			EnvVar: "GOSS_VARS_INLINE",
		},
		cli.StringFlag{
			Name:  "package",
			Usage: fmt.Sprintf("Package type to use [%s]", strings.Join(system.SupportedPackageManagers(), ", ")),
		},
	}
	app.Commands = []cli.Command{
		{
			Name:    "validate",
			Aliases: []string{"v"},
			Usage:   "Validate system",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "format, f",
					Value:  "rspecish",
					Usage:  fmt.Sprintf("Format to output in, valid options: %s", outputs.Outputers()),
					EnvVar: "GOSS_FMT",
				},
				cli.StringSliceFlag{
					Name:   "format-options, o",
					Usage:  fmt.Sprintf("Extra options passed to the formatter, valid options: %s", outputs.FormatOptions()),
					EnvVar: "GOSS_FMT_OPTIONS",
				},
				cli.BoolFlag{
					Name:   "color",
					Usage:  "Force color on",
					EnvVar: "GOSS_COLOR",
				},
				cli.BoolFlag{
					Name:   "no-color",
					Usage:  "Force color off",
					EnvVar: "GOSS_NOCOLOR",
				},
				cli.DurationFlag{
					Name:   "sleep,s",
					Usage:  "Time to sleep between retries, only active when -r is set",
					Value:  1 * time.Second,
					EnvVar: "GOSS_SLEEP",
				},
				cli.DurationFlag{
					Name:   "retry-timeout,r",
					Usage:  "Retry on failure so long as elapsed + sleep time is less than this",
					Value:  0,
					EnvVar: "GOSS_RETRY_TIMEOUT",
				},
				cli.IntFlag{
					Name:   "max-concurrent",
					Usage:  "Max number of tests to run concurrently",
					Value:  50,
					EnvVar: "GOSS_MAX_CONCURRENT",
				},
				cli.StringFlag{
					Name:   "last-output",
					Value:  "",
					Usage:  fmt.Sprintf("File to save last validate output"),
					EnvVar: "GOSS_LAST_OUTPUT",
				},
			},
			Action: func(c *cli.Context) error {
				fatalAlphaIfNeeded(c)
				code, err := goss.Validate(newRuntimeConfigFromCLI(c), startTime)
				if err != nil {
					color.Red(fmt.Sprintf("Error: %v\n", err))
				}
				os.Exit(code)

				return nil
			},
		},
		{
			Name:    "serve",
			Aliases: []string{"s"},
			Usage:   "Serve a health endpoint",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "format, f",
					Value:  "rspecish",
					Usage:  fmt.Sprintf("Format to output in, valid options: %s", outputs.Outputers()),
					EnvVar: "GOSS_FMT",
				},
				cli.StringSliceFlag{
					Name:   "format-options, o",
					Usage:  fmt.Sprintf("Extra options passed to the formatter, valid options: %s", outputs.FormatOptions()),
					EnvVar: "GOSS_FMT_OPTIONS",
				},
				cli.DurationFlag{
					Name:   "cache,c",
					Usage:  "Time to cache the results",
					Value:  5 * time.Second,
					EnvVar: "GOSS_CACHE",
				},
				cli.StringFlag{
					Name:   "listen-addr,l",
					Value:  ":8080",
					Usage:  "Address to listen on [ip]:port",
					EnvVar: "GOSS_LISTEN",
				},
				cli.StringFlag{
					Name:   "endpoint,e",
					Value:  "/healthz",
					Usage:  "Endpoint to expose",
					EnvVar: "GOSS_ENDPOINT",
				},
				cli.IntFlag{
					Name:   "max-concurrent",
					Usage:  "Max number of tests to run concurrently",
					Value:  50,
					EnvVar: "GOSS_MAX_CONCURRENT",
				},
			},
			Action: func(c *cli.Context) error {
				fatalAlphaIfNeeded(c)
				return goss.Serve(newRuntimeConfigFromCLI(c))
			},
		},
		{
			Name:    "render",
			Aliases: []string{"r"},
			Usage:   "render gossfile after imports",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "debug, d",
					Usage: fmt.Sprintf("Print debugging info when rendering"),
				},
			},
			Action: func(c *cli.Context) error {
				fatalAlphaIfNeeded(c)
				j, err := goss.RenderJSON(newRuntimeConfigFromCLI(c))
				if err != nil {
					return err
				}

				fmt.Print(j)

				return nil
			},
		},
		{
			Name:    "autoadd",
			Aliases: []string{"aa"},
			Usage:   "automatically add all matching resource to the test suite",
			Action: func(c *cli.Context) error {
				fatalAlphaIfNeeded(c)
				return goss.AutoAddResources(c.GlobalString("gossfile"), c.Args(), newRuntimeConfigFromCLI(c))
			},
		},
		{
			Name:    "add",
			Aliases: []string{"a"},
			Usage:   "add a resource to the test suite",
			Flags: []cli.Flag{
				cli.StringSliceFlag{
					Name:  "exclude-attr",
					Usage: "Exclude the following attributes when adding a new resource",
				},
			},
			Subcommands: []cli.Command{
				{
					Name:  "package",
					Usage: "add new package",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Package", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "file",
					Usage: "add new file",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "File", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "addr",
					Usage: "add new remote address:port - ex: google.com:80",
					Flags: []cli.Flag{
						timeoutFlag(500 * time.Millisecond),
					},
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Addr", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "port",
					Usage: "add new listening [protocol]:port - ex: 80 or udp:123",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Port", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "service",
					Usage: "add new service",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Service", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "user",
					Usage: "add new user",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "User", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "group",
					Usage: "add new group",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Group", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "command",
					Usage: "add new command",
					Flags: []cli.Flag{
						timeoutFlag(10 * time.Second),
					},
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Command", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "dns",
					Usage: "add new dns",
					Flags: []cli.Flag{
						timeoutFlag(500 * time.Millisecond),
						cli.StringFlag{
							Name:  "server",
							Usage: "The IP address of a DNS server to query",
						},
					},
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "DNS", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "process",
					Usage: "add new process name",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Process", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "http",
					Usage: "add new http",
					Flags: []cli.Flag{
						cli.BoolFlag{
							Name: "insecure, k",
						},
						cli.BoolFlag{
							Name: "no-follow-redirects, r",
						},
						timeoutFlag(5 * time.Second),
						cli.StringFlag{
							Name:  "username, u",
							Usage: "Username for basic auth",
						},
						cli.StringFlag{
							Name:  "password, p",
							Usage: "Password for basic auth",
						},
						cli.StringFlag{
							Name:  "cert",
							Usage: "TLS cert file for mutual tls",
						},
						cli.StringFlag{
							Name:  "key",
							Usage: "TLS key file for mutual tls",
						},
						cli.StringFlag{
							Name:  "cacert",
							Usage: "custom CA cert file for tls",
						},
						cli.StringFlag{
							Name:  "proxy, x",
							Usage: "Proxy server to use. e.g. http://10.0.0.2:8080",
						},
					},
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "HTTP", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "goss",
					Usage: "add new goss file, it will be imported from this one",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Gossfile", c.Args(), newRuntimeConfigFromCLI(c))

					},
				},
				{
					Name:  "kernel-param",
					Usage: "add new goss kernel param",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "KernelParam", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "mount",
					Usage: "add new mount",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Mount", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
				{
					Name:  "interface",
					Usage: "add new interface",
					Action: func(c *cli.Context) error {
						fatalAlphaIfNeeded(c)
						return goss.AddResources(c.GlobalString("gossfile"), "Interface", c.Args(), newRuntimeConfigFromCLI(c))
					},
				},
			},
		},
	}

	addAlphaFlagIfNeeded(app)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func addAlphaFlagIfNeeded(app *cli.App) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		app.Flags = append(app.Flags, cli.StringFlag{
			Name:   "use-alpha",
			Usage:  fmt.Sprintf("goss is alpha-quality. Set to 1 to use anyway."),
			EnvVar: "GOSS_USE_ALPHA",
			Value:  "0",
		})
	}
}

const msgFormat string = `WARNING: goss for this platform (%q) is alpha-quality, work-in-progress, and not yet exercised within continuous integration.

You should not expect everything to work. Treat linux as the canonical behaviour to expect.

Please see https://github.com/aelsabbahy/goss/tree/master/docs/platform-feature-parity.md to set your expectations and see progress.
Please file issues via https://github.com/aelsabbahy/goss/issues/new/choose
Pull requests and bug reports very welcome.`

func fatalAlphaIfNeeded(c *cli.Context) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		if c.GlobalString("use-alpha") != "1" {
			howto := map[string]string{
				"darwin":  "export GOSS_USE_ALPHA=1",
				"windows": "In cmd:        set GOSS_USE_ALPHA=1\nIn powershell: $env:GOSS_USE_ALPHA=1\nIn bash:       export GOSS_USE_ALPHA=1",
			}
			log.Printf(`Terminating.

To bypass this and use the binary anyway:

%s`, howto[runtime.GOOS])
			os.Exit(1)
		}
	}
}

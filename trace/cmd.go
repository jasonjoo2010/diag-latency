package trace

import "github.com/urfave/cli/v2"

func TraceCommand() *cli.Command {
	return &cli.Command{
		Name: "trace",
		Subcommands: []*cli.Command{
			{
				Name:   "one",
				Action: oneAction,
				Flags: []cli.Flag{
					&cli.IntSliceFlag{
						Name: "port",
					},
					&cli.StringSliceFlag{
						Name: "ip",
					},
				},
			},
		},
	}
}

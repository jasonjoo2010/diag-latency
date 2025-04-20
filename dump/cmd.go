package dump

import "github.com/urfave/cli/v2"

func DumpCommand() *cli.Command {
	return &cli.Command{
		Name: "dump",
		Subcommands: []*cli.Command{
			{
				Name:   "raw",
				Action: dumpAction,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "dev",
						Required: true,
					},
					&cli.IntSliceFlag{
						Name: "port",
					},
					&cli.StringSliceFlag{
						Name: "ip",
					},
				},
			},
			{
				Name: "lat",
				Action: func(ctx *cli.Context) error {
					return nil
				},
			},
		},
	}
}

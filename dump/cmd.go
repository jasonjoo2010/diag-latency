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
					&cli.StringSliceFlag{
						Name: "local-ip",
					},
					&cli.IntSliceFlag{
						Name: "remote-port",
					},
				},
				Action: latAction,
			},
		},
	}
}

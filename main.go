package main

import (
	"fmt"
	"os"

	"github.com/jasonjoo2010/diag-latency/dump"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			dump.DumpCommand(),
		},
		ExitErrHandler: func(cCtx *cli.Context, err error) {
			if err == nil {
				return
			}

			fmt.Println("err:", err)
		},
	}

	app.Run(os.Args)
}

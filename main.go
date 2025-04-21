package main

import (
	"fmt"
	"os"

	"github.com/jasonjoo2010/diag-latency/dump"
	"github.com/jasonjoo2010/diag-latency/trace"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			dump.DumpCommand(),
			trace.TraceCommand(),
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

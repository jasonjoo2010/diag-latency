package trace

import "github.com/urfave/cli/v2"

func oneAction(ctx *cli.Context) error {
	ips := ctx.StringSlice("ip")
	ports := ctx.IntSlice("port")
	return nil
}

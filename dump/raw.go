package dump

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"
)

func dumpAction(ctx *cli.Context) error {
	dev := ctx.String("dev")
	ips := ctx.StringSlice("ip")
	ports := ctx.IntSlice("port")
	conds := make([]string, 0, len(ips)+len(ports))
	for _, ip := range ips {
		conds = append(conds, "host "+ip)
	}
	for _, p := range ports {
		conds = append(conds, fmt.Sprint("port ", p))
	}
	h, err := pcap.OpenLive(dev, 65535, true, time.Second)
	if err != nil {
		return err
	}
	defer h.Close()

	if len(conds) > 0 {
		err = h.SetBPFFilter(strings.Join(conds, " and "))
		if err != nil {
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	start := time.Now()
NEXT_PKT:
	for p := range packetSource.Packets() {
		var from, to net.IP
		for _, l := range p.Layers() {
			switch l.LayerType() {
			case layers.LayerTypeIPv4:
				ip := l.(*layers.IPv4)
				from = ip.SrcIP
				to = ip.DstIP
			case layers.LayerTypeIPv6:
				ip := l.(*layers.IPv6)
				from = ip.SrcIP
				to = ip.DstIP
			case layers.LayerTypeUDP:
				continue NEXT_PKT
			case layers.LayerTypeTCP:
				tcp := l.(*layers.TCP)
				if len(tcp.Payload) == 0 {
					continue NEXT_PKT
				}

				cost := p.Metadata().Timestamp.Sub(start)
				fmt.Printf("%010d.%03d %s:%d => %s:%d: len=%d\n", cost.Milliseconds(), cost.Microseconds()%1000, from.String(), tcp.SrcPort, to.String(), tcp.DstPort, len(tcp.Payload))
			}
		}
	}

	return nil
}

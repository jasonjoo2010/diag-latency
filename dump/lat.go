package dump

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli/v2"
)

const (
	LastPkgTypeRequest  = 0
	LastPkgTypeResponse = 1
)

type pktEndpoint struct {
	IP   [2]uint64
	Port uint16
}

type pktKey struct {
	Local, Remote pktEndpoint
}

type pktState struct {
	Time        time.Time
	LastPkgType int
}

func ip2long(ip net.IP) (ret [2]uint64) {
	for i, b := range ip {
		ret[i/8] |= uint64(b) << ((i % 8) * 8)
	}
	return
}

func sliceToMap[T comparable](arr []T) map[T]bool {
	result := make(map[T]bool, len(arr))
	for _, item := range arr {
		result[item] = true
	}

	return result
}

func convIPString2Long(ipStr string) [2]uint64 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		panic("malformed ip: " + ipStr)
	}

	ip4 := ip.To4()
	if ip4 != nil {
		return ip2long(ip4)
	}
	return ip2long(ip)
}

func convert[V1, V2 any](arr []V1, f func(V1) V2) []V2 {
	result := make([]V2, len(arr))
	for i, v := range arr {
		result[i] = f(v)
	}

	return result
}

func latAction(ctx *cli.Context) error {
	dev := ctx.String("dev")
	ips := ctx.StringSlice("ip")
	ports := ctx.IntSlice("port")
	localIPs := sliceToMap(convert(ctx.StringSlice("local-ip"), convIPString2Long))
	remotePorts := sliceToMap(ctx.IntSlice("remote-port"))
	if len(localIPs)+len(remotePorts) == 0 {
		return errors.New("local ip/port is required")
	}

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

	pktMap := make(map[pktKey]*pktState, 1024)
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
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

				fromIPLong := ip2long(from)
				toIPLong := ip2long(to)
				// fmt.Println(from.String(), fromIPLong, localIPs[fromIPLong])
				isRequest := localIPs[fromIPLong] || remotePorts[int(tcp.DstPort)]
				pktType := LastPkgTypeRequest
				var key pktKey
				key.Local, key.Remote = pktEndpoint{fromIPLong, uint16(tcp.SrcPort)}, pktEndpoint{toIPLong, uint16(tcp.DstPort)}
				if !isRequest {
					key.Local, key.Remote = key.Remote, key.Local
					pktType = LastPkgTypeResponse
				}
				// fmt.Println(isRequest)

				s, ok := pktMap[key]
				if !ok {
					pktMap[key] = &pktState{
						Time:        p.Metadata().Timestamp,
						LastPkgType: pktType,
					}
					continue NEXT_PKT
				}

				if s.LastPkgType == LastPkgTypeRequest && pktType == LastPkgTypeResponse {
					cost := p.Metadata().Timestamp.Sub(s.Time)
					fmt.Printf("1st response: %s %03d.%03d %s:%d => %s:%d, len=%d\n", p.Metadata().Timestamp.Format("2006-01-02 15:04:05.000"), cost.Milliseconds(), cost.Microseconds()%1000, from.String(), tcp.SrcPort, to.String(), tcp.DstPort, len(tcp.Payload))
				} else if s.LastPkgType == LastPkgTypeResponse && pktType == LastPkgTypeResponse {
					cost := p.Metadata().Timestamp.Sub(s.Time)
					fmt.Printf("following response: %s %03d.%03d %s:%d => %s:%d, len=%d\n", p.Metadata().Timestamp.Format("2006-01-02 15:04:05.000"), cost.Milliseconds(), cost.Microseconds()%1000, from.String(), tcp.SrcPort, to.String(), tcp.DstPort, len(tcp.Payload))
				}
				s.Time = p.Metadata().Timestamp
				s.LastPkgType = pktType
			}
		}
	}

	return nil
}

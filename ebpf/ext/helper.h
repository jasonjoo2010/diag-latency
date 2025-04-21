#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })

#define READ_USER(ptr)                                          \
    ({                                                          \
        typeof(ptr) _val;                                       \
        __builtin_memset((void *)&_val, 0, sizeof(_val));       \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr); \
        _val;                                                   \
    })

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define ETH_ALEN 6
#define ETH_P_802_3_MIN 0x0600
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMPV6 58

#define ARP_OP_REQUEST 0x0001
#define ARP_OP_REPLY 0x0002

#define TCP_EVENT_CONNECT 1
#define TCP_EVENT_ACCEPT 2
#define TCP_EVENT_CLOSE 3

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define ETH_P_VLAN 0x8100 /* Virtual Lan 802.1Q        */

#define ETH_HLEN sizeof(struct ethhdr)
#define VLAN_HLEN sizeof(struct vlan_hdr)
#define IP_HLEN sizeof(struct iphdr)
#define IP6_HLEN sizeof(struct ipv6hdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define DNS_HLEN sizeof(struct dns_hdr)
#define ARP_HLEN sizeof(struct arphdr)
#define ARP_RLEN 20 // mac|ipv4 x src|dst
#define ctx_ptr(field) (void *)(long)(field)

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator / Drop Eligible Indicator */
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_N_VID		4096

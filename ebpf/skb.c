#include "bpf/vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"
#include "bpf/builtins.h"
#include "ext/helper.h"

#define ROUTE_EVENT_IF 		0x0001
#define ROUTE_EVENT_IPTABLE	0x0002
#define ROUTE_EVENT_DROP 	0x0004
#define ROUTE_EVENT_NEW 	0x0010

#ifdef __BCC_ARGS__
__BCC_ARGS_DEFINE__
#else
#define __BCC_pid        0
#define __BCC_ipaddr     0
#define __BCC_ipaddr1     0
#define __BCC_port       0
#define __BCC_icmpid     0
#define __BCC_dropstack  0
#define __BCC_callstack  0
#define __BCC_iptable    0
#define __BCC_route      0
#define __BCC_keep       0
#define __BCC_proto      0
#define __BCC_netns      0
#endif

/* route info as default  */
#if !__BCC_dropstack && !__BCC_iptable && !__BCC_route
#undef __BCC_route
#define __BCC_route      1
#endif

#if (__BCC_dropstack) || (!__BCC_pid && !__BCC_ipaddr && !__BCC_port && !__BCC_icmpid &&! __BCC_proto && !__BCC_netns)
#undef __BCC_keep
#define __BCC_keep 0
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef XT_TABLE_MAXNAMELEN
#define XT_TABLE_MAXNAMELEN 32
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#endif

#ifndef tcp_flag_word
#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3])
#endif

#ifndef SKB_DST_PTRMASK
#define SKB_DST_NOREF	1UL
#define SKB_DST_PTRMASK	~(SKB_DST_NOREF)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 2048);
    __type(key, u32);
    __type(value, u64[100]);
} stacks SEC(".maps");

#define FUNCNAME_MAX_LEN 64
struct event_t {
    char func_name[FUNCNAME_MAX_LEN];
    u8 flags;
    u8 cpu;

    // route info
    char ifname[IFNAMSIZ];
    u32  netns;

    // pkt info
    u8 dest_mac[6];
    u32 len;
    u8 ip_version;
    u8 l4_proto;
    u16 tot_len;
    u64 saddr[2];
    u64 daddr[2];
    u8 icmptype;
    u16 icmpid;
    u16 icmpseq;
    u16 sport;
    u16 dport;
    u16 tcpflags;

    // ipt info
    u32 hook;
    u8 pf;
    u32 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
    u64 ipt_delay;

    void *skb;
    // skb info
    u8 pkt_type; //skb->pkt_type
//    unsigned long _nfct;

    // call stack
    int kernel_stack_id;
    u64 kernel_ip;

    //time
    u64 start_ns;
    u32 iptable_entry;
    u16 vlan_tci;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} route_event SEC(".maps");

#if __BCC_iptable
struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    u64 start_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct ipt_do_table_args);
} cur_ipt_do_table_args SEC(".maps");
#endif

enum br_pkt_type {
	BR_PKT_UNICAST,
	BR_PKT_MULTICAST,
	BR_PKT_BROADCAST
};

union ___skb_pkt_type {
    __u8 value;
    struct {
        __u8			__pkt_type_offset[0];
        __u8			pkt_type:3;
        __u8			pfmemalloc:1;
        __u8			ignore_df:1;

        __u8			nf_trace:1;
        __u8			ip_summed:2;
    };
};

#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)            \
    ({                                                          \
        void* __ret;                                            \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                  \
    })
#define member_read(destination, source_struct, source_member)  \
  do{                                                           \
    bpf_probe_read(                                             \
      destination,                                              \
      sizeof(source_struct->source_member),                     \
      member_address(source_struct, source_member)              \
    );                                                          \
  } while(0)

enum {
__TCP_FLAG_CWR,
__TCP_FLAG_ECE,
__TCP_FLAG_URG,
__TCP_FLAG_ACK,
__TCP_FLAG_PSH,
__TCP_FLAG_RST,
__TCP_FLAG_SYN,
__TCP_FLAG_FIN
};

static void bpf_strncpy(char *dst, const char *src, int n)
{
    int i = 0, j;
#define CPY(n) \
    do { \
        for (; i < n; i++) { \
            if (src[i] == 0) return; \
            dst[i] = src[i]; \
        } \
    } while(0)

    for (j = 10; j < 64; j += 10)
    	CPY(j);
    CPY(64);
#undef CPY
}

#define TCP_FLAGS_INIT(new_flags, orig_flags, flag) \
    do { \
        if (orig_flags & flag) { \
            new_flags |= (1U<<__##flag); \
        } \
    } while (0)
#define init_tcpflags_bits(new_flags, orig_flags) \
    ({ \
        new_flags = 0; \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_CWR); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_ECE); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_URG); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_ACK); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_PSH); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_RST); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_SYN); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_FIN); \
    })

static void get_stack(struct pt_regs *ctx, struct event_t *event)
{
    event->kernel_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    if (event->kernel_stack_id >= 0) {
        u64 ip = PT_REGS_IP(ctx);
        u64 page_offset = 0;
        // if ip isn't sane, leave key ips as zero for later checking
#if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
#elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
#if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
#else
        page_offset = __PAGE_OFFSET_BASE_L4;
#endif

#elif defined(PAGE_OFFSET)
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
#endif
        if (ip > page_offset) {
            event->kernel_ip = ip;
        }
    }
    return;
}

#define CALL_STACK(ctx, event) \
do { \
if (__BCC_callstack) \
    get_stack(ctx, event); \
} while (0)


/**
  * Common tracepoint handler. Detect IPv4/IPv6 and
  * emit event with address, interface and namespace.
  */
static int
do_trace_skb(struct event_t *event, void *ctx, struct sk_buff *skb, void *netdev)
{
    struct net_device *dev;

    char *head;
    char *l2_header_address;
    char *l3_header_address;
    char *l4_header_address;

    u16 mac_header;
    u16 network_header;

    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 l4_offset_from_ip_header;

    struct icmphdr icmphdr;
    union tcp_word_hdr tcphdr;
    struct udphdr udphdr;

    // Get device pointer, we'll need it to get the name and network namespace
    event->ifname[0] = 0;
    if (netdev)
        dev = netdev;
    else
        member_read(&dev, skb, dev);

    bpf_probe_read(&event->ifname, IFNAMSIZ, dev->name);

    if (event->ifname[0] == 0 || dev == NULL)
        bpf_strncpy(event->ifname, "nil", IFNAMSIZ);

    event->flags |= ROUTE_EVENT_IF;

#ifdef CONFIG_NET_NS
    struct net* net;

    // Get netns id. The code below is equivalent to: event->netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common *ns = member_address(net, ns);
    member_read(&event->netns, ns, inum);

    // maybe the skb->dev is not init, for this situation, we can get ns by sk->__sk_common.skc_net.net->ns.inum
    if (event->netns == 0) {
        struct sock *sk;
        struct sock_common __sk_common;
        struct ns_common* ns2;
        member_read(&sk, skb, sk);
        if (sk != NULL) {
            member_read(&__sk_common, sk, __sk_common);
            ns2 = member_address(__sk_common.skc_net.net, ns);
            member_read(&event->netns, ns2, inum);
        }
    }


#endif
    event->cpu = bpf_get_smp_processor_id();
    member_read(&event->len, skb, len);
    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if(network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    l2_header_address = mac_header + head;
    bpf_probe_read(&event->dest_mac, 6, l2_header_address);

    l3_header_address = head + network_header;
    bpf_probe_read(&event->ip_version, sizeof(u8), l3_header_address);
    event->ip_version = event->ip_version >> 4 & 0xf;

    if (event->ip_version == 4) {
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), l3_header_address);

        l4_offset_from_ip_header = iphdr.ihl * 4;
        event->l4_proto  = iphdr.protocol;
        event->saddr[0] = iphdr.saddr;
        event->daddr[0] = iphdr.daddr;
	    event->tot_len = bpf_ntohs(iphdr.tot_len);

	    if (event->l4_proto == IPPROTO_ICMP) {
       	    proto_icmp_echo_request = ICMP_ECHO;
       	    proto_icmp_echo_reply   = ICMP_ECHOREPLY;
        }

    } else if (event->ip_version == 6) {
        // Assume no option header --> fixed size header
        struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)l3_header_address;
        l4_offset_from_ip_header = sizeof(*ipv6hdr);

        bpf_probe_read(&event->l4_proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(event->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(event->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));
	    bpf_probe_read(&event->tot_len, sizeof(ipv6hdr->payload_len), (char*)ipv6hdr + offsetof(struct ipv6hdr, payload_len));
        event->tot_len = bpf_ntohs(event->tot_len);

	    if (event->l4_proto == IPPROTO_ICMPV6) {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply   = ICMPV6_ECHO_REPLY;
        }

    } else {
        return -1;
    }

    l4_header_address = l3_header_address + l4_offset_from_ip_header;
    switch (event->l4_proto) {
    case IPPROTO_ICMPV6:
    case IPPROTO_ICMP:
        bpf_probe_read(&icmphdr, sizeof(icmphdr), l4_header_address);
        if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
            return -1;
        }
        event->icmptype = icmphdr.type;
        event->icmpid   = __bpf_be16_to_cpu(icmphdr.un.echo.id);
        event->icmpseq  = __bpf_be16_to_cpu(icmphdr.un.echo.sequence);
        break;
    case IPPROTO_TCP:
        bpf_probe_read(&tcphdr, sizeof(tcphdr), l4_header_address);
        init_tcpflags_bits(event->tcpflags, tcp_flag_word(&tcphdr));
        event->sport = __bpf_be16_to_cpu(tcphdr.hdr.source);
        event->dport = __bpf_be16_to_cpu(tcphdr.hdr.dest);
        break;
    case IPPROTO_UDP:
        bpf_probe_read(&udphdr, sizeof(udphdr), l4_header_address);
        event->sport = __bpf_be16_to_cpu(udphdr.source);
        event->dport = __bpf_be16_to_cpu(udphdr.dest);
        break;
    default:
        return -1;
    }

#if __BCC_keep
#endif


    /*
     * netns filter
     */
    if (__BCC_netns !=0 && event->netns != 0 && event->netns != __BCC_netns) {
        return -1;
    }

    /*
     * pid filter
     */
#if __BCC_pid
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid != __BCC_pid)
        return -1;
#endif

    /*
     * addr filter
     */
#if __BCC_ipaddr
#if __BCC_ipaddr1
    // ipv6
    if (event->ip_version == 4)
        return -1;
    
    if ((__BCC_ipaddr != event->saddr[0] || __BCC_ipaddr1 != event->saddr[1]) && 
        (__BCC_ipaddr != event->daddr[0] || __BCC_ipaddr1 != event->daddr[1]))
        return -1;
#else
    // ipv4
    if (event->ip_version == 6)
        return -1;

    if (__BCC_ipaddr != event->saddr[0] && __BCC_ipaddr != event->daddr[0])
        return -1;
#endif
#endif

#if __BCC_proto
   if (__BCC_proto != event->l4_proto)
       return -1;
#endif

#if __BCC_port
   if ( (event->l4_proto == IPPROTO_UDP || event->l4_proto == IPPROTO_TCP) &&
	(__BCC_port != event->sport && __BCC_port != event->dport))
       return -1;
#endif

#if __BCC_icmpid
   if (__BCC_proto == IPPROTO_ICMP && __BCC_icmpid != event->icmpid)
       return -1;
#endif

#if __BCC_keep
#endif

    return 0;
}

static void dump_rt(struct sk_buff *skb, const char *func_name) {
   struct dst_entry *dst = (struct dst_entry *)(skb->_skb_refdst & SKB_DST_PTRMASK);
   const struct rtable *rt = container_of(dst, struct rtable, dst);
   //char buf[200] = {0};
   //bpf_strncpy(buf, func_name, 199);
   __bpf_printk("neigh: %d %u, %s", rt->rt_gw_family, rt->rt_gw4, func_name);
}

static int
do_trace(void *ctx, struct sk_buff *skb, const char *func_name, void *netdev, u8 *processed)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};

    if (do_trace_skb(&event, ctx, skb, netdev) < 0)
        return 0;

    event.skb=skb;
    bpf_probe_read(&type.value, 1, ((char*)skb) + offsetof(typeof(*skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;
//event._nfct = skb->_nfct;

    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, func_name, FUNCNAME_MAX_LEN);
    dump_rt(skb, event.func_name);
    event.iptable_entry = skb->_nfct;
    event.vlan_tci = skb->vlan_tci;
    // __bpf_printk("vlan: %u", event.vlan_tci);
    CALL_STACK(ctx, &event);
    bpf_perf_event_output(ctx, &route_event, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (processed)
        *processed = 1;

    return 0;
}

#if __BCC_route

/*
 * netif rcv hook:
 * 1) int netif_rx(struct sk_buff *skb)
 * 2) int __netif_receive_skb(struct sk_buff *skb)
 * 3) gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
 * 4) ...
 */
SEC("kprobe/netif_rx")
int BPF_KPROBE(netif_rx, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/enqueue_to_backlog")
int BPF_KPROBE(enqueue_to_backlog, struct sk_buff *skb, int cpu, unsigned int *qtail)
{
    return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/__netif_receive_skb")
int BPF_KPROBE(__netif_receive_skb, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/tpacket_rcv")
int BPF_KPROBE(tpacket_rcv, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    return do_trace(ctx, skb, __func__+8, orig_dev, NULL);
}

SEC("kprobe/packet_rcv")
int BPF_KPROBE(packet_rcv, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    return do_trace(ctx, skb, __func__+8, orig_dev, NULL);
}

SEC("kprobe/napi_gro_receive")
int BPF_KPROBE(napi_gro_receive, struct napi_struct *napi, struct sk_buff *skb)
{
    return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

/*
 * netif send hook:
 * 1) int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
 * 2) ...
 */
SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(__dev_queue_xmit, struct sk_buff *skb, struct net_device *sb_dev)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

/*
 * br process hook:
 * 1) rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
 * 2) int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) unsigned int br_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
 * 4) int br_nf_pre_routing_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int br_pass_frame_up(struct sk_buff *skb)
 * 6) int br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 7) void br_forward(const struct net_bridge_port *to, struct sk_buff *skb, bool local_rcv, bool local_orig)
 * 8) int br_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 9) unsigned int br_nf_forward_ip(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 10)int br_nf_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 11)unsigned int br_nf_post_routing(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 12)int br_nf_dev_queue_xmit(struct net *net, struct sock *sk, struct sk_buff *skb)
 */
SEC("kprobe/br_handle_frame")
int BPF_KPROBE(br_handle_frame, struct sk_buff **pskb)
{
   return do_trace(ctx, *pskb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_handle_frame_finish")
int BPF_KPROBE(br_handle_frame_finish, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_pre_routing")
int BPF_KPROBE(br_nf_pre_routing, void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_pre_routing_finish")
int BPF_KPROBE(br_nf_pre_routing_finish, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_pre_routing_finish_bridge")
int BPF_KPROBE(br_nf_pre_routing_finish_bridge, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/skb_push")
int BPF_KPROBE(skb_push, struct sk_buff *skb, unsigned int len)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_hook_thresh")
int BPF_KPROBE(br_nf_hook_thresh, unsigned int hook, struct net *net,
		      struct sock *sk, struct sk_buff *skb,
		      struct net_device *indev,
		      struct net_device *outdev)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_route_input_noref")
int BPF_KPROBE(ip_route_input_noref, struct sk_buff *skb, __be32 dst, __be32 src, u8 tos, struct net_device *devin) {
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_route_input_slow")
int BPF_KPROBE(ip_route_input_slow, struct sk_buff *skb, __be32 daddr, __be32 saddr,
			       u8 tos, struct net_device *dev,
			       struct fib_result *res)
{
   u8 processed = 0;
   int ret = do_trace(ctx, skb, __func__+8, NULL, &processed);
   if (processed) {
      struct fib_nh_common *nhc = (*res).nhc;
      struct rtable *rt = nhc->nhc_rth_input;
      __bpf_printk("route slow: => %u, %d %u", daddr, rt->rt_gw_family, rt->rt_gw4);
   }
   return ret;
}

SEC("kprobe/__mkroute_input")
int BPF_KPROBE(__mkroute_input, struct sk_buff *skb,
			   const struct fib_result *res,
			   struct in_device *in_dev,
			   __be32 daddr, __be32 saddr, u32 tos)
{
   u8 processed = 0;
   int ret = do_trace(ctx, skb, __func__+8, NULL, &processed);
   if (processed) {
      struct fib_nh_common *nhc = (*res).nhc;
      struct rtable *rt = nhc->nhc_rth_input;
      __bpf_printk("mkroute: => %u, %d %u", daddr, rt->rt_gw_family, rt->rt_gw4);
   }
   return ret;
}

SEC("kprobe/nf_bridge_update_protocol")
int BPF_KPROBE(nf_bridge_update_protocol, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_forward")
int BPF_KPROBE(ip_forward, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_handle_martian_source")
int BPF_KPROBE(ip_handle_martian_source, struct net_device *dev,
				     struct in_device *in_dev,
				     struct sk_buff *skb,
				     __be32 daddr,
				     __be32 saddr)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_pass_frame_up")
int BPF_KPROBE(br_pass_frame_up, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_netif_receive_skb")
int BPF_KPROBE(br_netif_receive_skb, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_forward")
int BPF_KPROBE(br_forward, const struct net_bridge_port *to, struct sk_buff *skb, bool local_rcv, bool local_orig)
{
    u8 processed = 0;
    int ret = do_trace(ctx, skb, __func__+8, NULL, &processed);
    if (processed) {
        __bpf_printk("br_forward: => %s", to->dev->name);
    }
    return ret;
}

// SEC("kprobe/__br_forward")
// int BPF_KPROBE(__br_forward, const void *to, struct sk_buff *skb, bool local_orig)
// {
//    return do_trace(ctx, skb, __func__+8, NULL, NULL);
// }

SEC("kprobe/br_flood")
int BPF_KPROBE(br_flood, struct net_bridge *br, struct sk_buff *skb, enum br_pkt_type pkt_type, bool local_rcv, bool local_orig)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_dev_xmit")
int BPF_KPROBE(br_dev_xmit, struct sk_buff *skb, struct net_device *dev)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ipv4_neigh_lookup")
int BPF_KPROBE(ipv4_neigh_lookup, const struct dst_entry *dst,
					   struct sk_buff *skb,
					   const void *daddr)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_forward_finish")
int BPF_KPROBE(br_forward_finish, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_forward_ip")
int BPF_KPROBE(br_nf_forward_ip, void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_forward_finish")
int BPF_KPROBE(br_nf_forward_finish, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_post_routing")
int BPF_KPROBE(br_nf_post_routing, void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(nf_hook_slow, struct sk_buff *skb, struct nf_hook_state *state,
		 const struct nf_hook_entries *e, unsigned int s)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/nft_nat_do_chain")
int BPF_KPROBE(nft_nat_do_chain, void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/resolve_normal_ct")
int BPF_KPROBE(resolve_normal_ct, struct nf_conn *tmpl,
		  struct sk_buff *skb,
		  unsigned int dataoff,
		  u_int8_t protonum,
		  const struct nf_hook_state *state)
{
    return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/nf_nat_ipv4_pre_routing")
int BPF_KPROBE(nf_nat_ipv4_pre_routing, void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/nf_nat_ipv4_out")
int BPF_KPROBE(nf_nat_ipv4_out, void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/nf_nat_ipv4_local_fn")
int BPF_KPROBE(nf_nat_ipv4_local_fn, void *priv, struct sk_buff *skb,
		     const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/nf_nat_ipv4_local_in")
int BPF_KPROBE(nf_nat_ipv4_local_in, void *priv, struct sk_buff *skb,
		     const struct nf_hook_state *state)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/br_nf_dev_queue_xmit")
int BPF_KPROBE(br_nf_dev_queue_xmit, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

/*
 * ip layer:
 * 1) int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
 * 2) int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 4) int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 6) ...
 */
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_rcv_finish")
int BPF_KPROBE(ip_rcv_finish, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_output")
int BPF_KPROBE(ip_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

SEC("kprobe/ip_finish_output")
int BPF_KPROBE(ip_finish_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
   return do_trace(ctx, skb, __func__+8, NULL, NULL);
}

#endif

#if __BCC_iptable
static int
__ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb,
		const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    args.start_ns = bpf_ktime_get_ns();
    cur_ipt_do_table_args.update(&pid, &args);

    return 0;
};

static int
__ipt_do_table_out(struct pt_regs * ctx, struct sk_buff *skb)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};
    struct ipt_do_table_args *args;
    u32 pid = bpf_get_current_pid_tgid();

    args = cur_ipt_do_table_args.lookup(&pid);
    if (args == 0)
        return 0;

    cur_ipt_do_table_args.delete(&pid);

    if (do_trace_skb(&event, ctx, args->skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_IPTABLE;
    event.ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    member_read(&event.hook, args->state, hook);
    member_read(&event.pf, args->state, pf);
    member_read(&event.tablename, args->table, name);
    event.verdict = PT_REGS_RC(ctx);
    event.skb=args->skb;
    bpf_probe_read(&type.value, 1, ((char*)args->skb) + offsetof(typeof(*args->skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;

    event.start_ns = bpf_ktime_get_ns();
    CALL_STACK(ctx, &event);
    route_event.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

SEC("kprobe/ipt_do_table")
int BPF_KPROBE(ipt_do_table, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

/*
 * tricky: use ebx as the 1st parms, thus get skb
 */
SEC("kretprobe/ipt_do_table")
int BPF_KRETPROBE(ipt_do_table)
{
    struct sk_buff *skb=(void*)ctx->bx;
    return __ipt_do_table_out(ctx, skb);
}
#endif


#if __BCC_dropstack
SEC("kprobe/__kfree_skb")
int BPF_KPROBE(__kfree_skb, struct sk_buff *skb)
{
    struct event_t event = {};

    if (do_trace_skb(&event, ctx, skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_DROP;
    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, __func__+8, FUNCNAME_MAX_LEN);
    get_stack(ctx, &event);
    route_event.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
#endif

#if 0
SEC("kprobe/ip6t_do_table")
int BPF_KPROBE(ip6t_do_table, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    return __ipt_do_table_in(ctx, skb, state, table);
};

SEC("kretprobe/ip6t_do_table")
int BPF_KPROBE(ip6t_do_table)
{
    return __ipt_do_table_out(ctx);
}
#endif

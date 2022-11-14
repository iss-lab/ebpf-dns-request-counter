#define DEBUG

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

/** Parts of the code is copied from NLNetLabs' xdp_dns_cookies_kern.c program
 ** (see https://github.com/NLnetLabs/XDPeriments)
*/
#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add(ptr, val))
#endif

struct vlanhdr
{
  __u16 tci;
  __u16 encap_proto;
};

struct dns_qrr
{
  __u16 qtype;
  __u16 qclass;
};

struct dns_rr
{
  __u16 type;
  __u16 class;
  __u32 ttl;
  __u16 rdata_len;
} __attribute__((packed));

struct option
{
  __u16 code;
  __u16 len;
  __u8 data[];
} __attribute__((packed));

struct dnshdr
{
  __u16 id;
  union
  {
    struct
    {
      __u8 rd : 1;
      __u8 tc : 1;
      __u8 aa : 1;
      __u8 opcode : 4;
      __u8 qr : 1;

      __u8 rcode : 4;
      __u8 cd : 1;
      __u8 ad : 1;
      __u8 z : 1;
      __u8 ra : 1;
    } as_bits_and_pieces;
    __u16 as_value;
  } flags;
  __u16 qdcount;
  __u16 ancount;
  __u16 nscount;
  __u16 arcount;
};

struct meta_data
{
  __u16 eth_proto;
  __u16 ip_pos;
  __u16 opt_pos;
  __u16 unused;
};

// eBPF map to store DNS requests
BPF_MAP_DEF(rqCounter) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};
BPF_MAP_ADD(rqCounter);


// Helper functions to parse the incoming packets
struct cursor
{
  void *pos;
  void *end;
};

static __always_inline void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
  c->end = (void *)(long)ctx->data_end;
  c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)                                   \
  static __always_inline struct STRUCT *parse_##STRUCT(struct cursor *c) \
  {                                                                      \
    struct STRUCT *ret = c->pos;                                         \
    if (c->pos + sizeof(struct STRUCT) > c->end)                         \
      return 0;                                                          \
    c->pos += sizeof(struct STRUCT);                                     \
    return ret;                                                          \
  }

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)
PARSE_FUNC_DECLARATION(dns_qrr)
PARSE_FUNC_DECLARATION(dns_rr)
PARSE_FUNC_DECLARATION(option)

static __always_inline struct ethhdr *parse_eth(struct cursor *c, __u16 *eth_proto)
{
  struct ethhdr *eth;

  if (!(eth = parse_ethhdr(c)))
    return 0;

  *eth_proto = eth->h_proto;
  if (*eth_proto == __bpf_htons(ETH_P_8021Q) || *eth_proto == __bpf_htons(ETH_P_8021AD))
  {
    struct vlanhdr *vlan;

    if (!(vlan = parse_vlanhdr(c)))
      return 0;

    *eth_proto = vlan->encap_proto;
    if (*eth_proto == __bpf_htons(ETH_P_8021Q) || *eth_proto == __bpf_htons(ETH_P_8021AD))
    {
      if (!(vlan = parse_vlanhdr(c)))
        return 0;

      *eth_proto = vlan->encap_proto;
    }
  }
  return eth;
}

#define DNS_PORT 53

// XDP program //
SEC("xdp")
int packet_count(struct xdp_md *ctx)
{
  struct meta_data *md = (void *)(long)ctx->data_meta;
  struct cursor c;
  struct ethhdr *eth;
  struct ipv6hdr *ipv6;
  struct iphdr *ipv4;
  struct udphdr *udp;
  struct dnshdr *dns;
  __u64 *count;

  if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
    return XDP_PASS;

  cursor_init(&c, ctx);
  md = (void *)(long)ctx->data_meta;
  if ((void *)(md + 1) > c.pos)
    return XDP_PASS;

  if (!(eth = parse_eth(&c, &md->eth_proto)))
    return XDP_PASS;
  md->ip_pos = c.pos - (void *)eth;

  if (md->eth_proto != __bpf_htons(ETH_P_IP))
  {
    return XDP_PASS;
  }

  if (!(ipv4 = parse_iphdr(&c)) || !(ipv4->protocol == IPPROTO_UDP))
  {
    return XDP_PASS;
  }

  udp = parse_udphdr(&c);
  if (!udp) {
    return XDP_PASS;
  }

  if (udp->source == __bpf_htons(DNS_PORT))
  {
  __u32 idx = 0;
  __u64 *counter = bpf_map_lookup_elem(&rqCounter, &idx);
  if (counter)
  {
    (*counter)++;
  }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
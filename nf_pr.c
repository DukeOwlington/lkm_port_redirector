#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define SOURCE_PORT 7777
#define DESTINATION_PORT 7778

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MadMax");
MODULE_DESCRIPTION("A simple Linux port redirector");
MODULE_VERSION("0.1");

/* This function to be called by hook */
static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
  struct udphdr *udp_header;
  struct tcphdr *tcp_header;

  switch (ip_header->protocol) {
    case IPPROTO_UDP:
      udp_header = (struct udphdr *)skb_transport_header(skb);
      if (udp_header->dest == htons(SOURCE_PORT)) {
        udp_header->dest = htons(DESTINATION_PORT);
        printk(KERN_INFO "UDP dest port has been redirected.\n");
      }
    case IPPROTO_TCP:
      tcp_header = (struct tcphdr *)skb_transport_header(skb);
      if (tcp_header->dest == htons(SOURCE_PORT)) {
        tcp_header->dest = htons(DESTINATION_PORT);
        printk(KERN_INFO "TCP dest port has been redirected.\n");
      }
  }
  return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = hook_func,              /* hook function */
    .hooknum = NF_INET_PRE_ROUTING, /* watch all packets */
    .pf = PF_INET,                  /* ip protocol family */
    .priority = NF_IP_PRI_FIRST,    /* high priority */
};

static int __init init_nf(void) {
  printk(KERN_INFO "Register netfilter module.\n");
  nf_register_hook(&nfho);

  return 0;
}

static void __exit exit_nf(void) {
  printk(KERN_INFO "Unregister netfilter module.\n");
  nf_unregister_hook(&nfho);
}

module_init(init_nf);
module_exit(exit_nf);

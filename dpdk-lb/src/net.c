#include <rte_arp.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include <base.h>
#include <net-config.h>

static int eth_out(struct rte_mbuf *pkt_buf, uint16_t h_proto,
				   struct rte_ether_addr *dst_haddr, uint16_t iplen)
{
	/* fill the ethernet header */
	struct rte_ether_hdr *hdr =
		rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);

	hdr->dst_addr = *dst_haddr;
	memcpy(&hdr->src_addr, local_mac, 6);
	hdr->ether_type = rte_cpu_to_be_16(h_proto);

	/* Print the packet */
	// pkt_dump(pkt_buf);

	/* enqueue the packet */
	pkt_buf->data_len = iplen + sizeof(struct rte_ether_hdr);
	pkt_buf->pkt_len = pkt_buf->data_len;
	dpdk_out(pkt_buf);

	return 0;
}

static void arp_reply(struct rte_mbuf *pkt, struct rte_arp_hdr *arph)
{
	arph->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	/* fill arp body */
	arph->arp_data.arp_tip = arph->arp_data.arp_sip;
	arph->arp_data.arp_sip = rte_cpu_to_be_32(local_ip);

	arph->arp_data.arp_tha = arph->arp_data.arp_sha;
	memcpy(&arph->arp_data.arp_sha, local_mac, 6);

	eth_out(pkt, RTE_ETHER_TYPE_ARP, &arph->arp_data.arp_tha,
			sizeof(struct rte_arp_hdr));
}

static void arp_in(struct rte_mbuf *pkt)
{
	struct rte_arp_hdr *arph = rte_pktmbuf_mtod_offset(
		pkt, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

	/* process only arp for this address */
	if (rte_be_to_cpu_32(arph->arp_data.arp_tip) != local_ip)
		goto OUT;

	switch (rte_be_to_cpu_16(arph->arp_opcode)) {
	case RTE_ARP_OP_REQUEST:
		arp_reply(pkt, arph);
		break;
	default:
		fprintf(stderr, "apr: Received unknown ARP op");
		goto OUT;
	}

	return;

OUT:
	rte_pktmbuf_free(pkt);
	return;
}

static struct rte_ether_addr *get_mac_for_ip(uint32_t ip)
{
	return &mac_addresses[(ip & 0xf) - 1];
}

static uint32_t get_target_ip(uint32_t src_ip, uint16_t src_port,
							  uint16_t dst_port)
{
	if (src_ip==0xa000002 || src_ip==0xa000003):
		targets[0] = 0xa000001;
	else:
		uint32_t hash_value = (src_ip ^ 6 ^ src_port ^ dst_port) % 2;
		if (hash_value==0):
			targets[0] = 0xa000002;
		else:
			targets[0] = 0xa000003;
	return targets[0];
}

static void lb_in(struct rte_mbuf *pkt_buf)
{
	struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod_offset(
		pkt_buf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	/* FIXME: Use the get_target_ip function to get the target server IP */
	uint32_t new_dst_ip = get_target_ip(iph->src_ip, iph->src_port, iph->dst_port);

	/* FIXME: Set the src and destination IPs */
	iph->src_ip = 0xa00000a;
	iph->dst_ip = new_dst_ip;

	/* FIXME: Fix the tcp and ip checksums */
	iph->hdr_checksum=0;
	iph->cksum = 0;

	iph->hdr_checksum = rte_ipv4_cksum(iph);
	iph->cksum = rte_ipv4_udptcp_cksum(rte_pktmbuf_mtod(pkt_buf,unsigned char *),pkt_buf->data_len - sizeof(struct rte_ether_hdr));
	
	/* Send the packet out */
	eth_out(pkt_buf, 0x0800, get_mac_for_ip(new_dst_ip), rte_pktmbuf_data_len(pkt_buf));
}

void eth_in(struct rte_mbuf *pkt_buf)
{
	unsigned char *payload = rte_pktmbuf_mtod(pkt_buf, unsigned char *);
	struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)payload;

	if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
		arp_in(pkt_buf);
	} else if (hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		lb_in(pkt_buf);
	} else {
		// printf("Unknown ether type: %" PRIu16 "\n",
		//	   rte_be_to_cpu_16(hdr->ether_type));
		rte_pktmbuf_free(pkt_buf);
	}
}

/*
 * (C) 2011 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap client to bridge two network interfaces
 * (or one interface and the host stack).
 *
 * $FreeBSD: release/10.0.0/tools/tools/netmap/bridge.c 251131 2013-05-30 11:09:41Z luigi $
 */

/* #include "nm_util.h" */
#include "of_zj.h"
/* #include "openflow-1.0.0.h" */

#define NO_SWAP

int verbose = 0;

char *version = "$Id$";

static int do_abort = 0;

static void
sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

/* print struct using HEX */
void printH(struct ofp_match *p)
{
  int i;
  char *p_char = (char *)p;

  for (i=0;i<sizeof(struct ofp_match);i++, p_char++)
  {
    printf("%02x ", *p_char);
  }
}
/* HEX to char* */
void unhexify(char *in,char *out){
	unsigned int ch;
	while(sscanf(in,"%2x",&ch)!=EOF){
		*out++=ch;
		in+=2;
	}
	*out='\0';
}

int actions(int act, unsigned char *buf, struct my_ring *dst)
{
    if(act == 1)
    {
        /*dst->queueid = 0x2000;*/
    }
}
/* match
int flow_match(Flow_Table t, struct sw_flow_key *key)
{
    for(i=0;i<ENTRY_NUM;++i)
    {
        if(t.entry[i].header.dl_src==key->eth.src && t.entry[i].header.dl_dst==key->eth.dst && t.entry[i].header.dl_type==key->eth.type){
            if(key->eth.type==0x0008){
                if(t.entry[i].header.nw_src==key->ipv4.addr.src && t.entry[i].header.nw_dst==key->ipv4.addr.dst)
            }
        }

    }
}*/

/*
struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *table,
				struct sw_flow_key *key, int key_len)
{
	struct sw_flow *flow = NULL;
	struct hlist_node *n;
	struct hlist_head *head;
	u8 *_key;
	int key_start;
	u32 hash;

	key_start = flow_key_start(key);
	hash = ovs_flow_hash(key, key_start, key_len);

	_key = (u8 *) key + key_start;
	head = find_bucket(table, hash);
	hlist_for_each_entry_rcu(flow, n, head, hash_node[table->node_ver]) {

		if (flow->hash == hash &&
		    !memcmp((u8 *)&flow->key + key_start, _key, key_len - key_start)) {
			return flow;
		}
	}
	return NULL;
}*/

/*
 * packet-dump function, user-supplied or static buffer.
 * The destination buffer must be at least 30+4*len
 */
 /*
unsigned char *
nm_dump_buf(char *p, int len, int lim, char *dst)
{
	static char _dst[8192];
	int i, j, i0;
	static char hex[] ="0123456789abcdef";
	char *o;	* output position *

#define P_HI(x)	hex[((x) & 0xf0)>>4]
#define P_LO(x)	hex[((x) & 0xf)]
#define P_C(x)	((x) >= 0x20 && (x) <= 0x7e ? (x) : '.')
	if (!dst)
		dst = _dst;
	if (lim <= 0 || lim > len)
		lim = len;
	o = dst;
*	sprintf(o, "buf 0x%p len %d lim %d\n", p, len, lim);
	o += strlen(o);*
	* hexdump routine *
	for (i = 0; i < lim; ) {
*		sprintf(o, "%5d: ", i);
		o += strlen(o);*
		memset(o, ' ', 32);
		i0 = i;
		for (j=0; j < 16 && i < lim; i++, j++) {
			o[j*2] = P_HI(p[i]);* mod *
			o[j*2+1] = P_LO(p[i]);* mod *
		}
		i = i0;
		for (j=0; j < 16 && i < lim; i++, j++)
*			o[j + 32] = P_C(p[i]);*
		o[j+32] = '\n';
		o += j*2+1;
	}
	*o = '\0';
#undef P_HI
#undef P_LO
#undef P_C
	return (unsigned char *)dst;
}*/

/*
 * move up to 'limit' pkts from rxring to txring swapping buffers.
 */
/* zhj */
static int
process_rings(struct netmap_ring *rxring, struct netmap_ring *txring,
	      u_int limit, const char *msg, Flow_Table t, struct my_ring *dst)
{
	u_int j, k, m = 0;/* zhj */

	/* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
	if (rxring->flags || txring->flags)
		D("%s rxflags %x txflags %x",
			msg, rxring->flags, txring->flags);
	j = rxring->cur; /* RX */
	k = txring->cur; /* TX */
	if (rxring->avail < limit)
		limit = rxring->avail;
	if (txring->avail < limit)
		limit = txring->avail;
	m = limit;
	while (limit-- > 0) {
		struct netmap_slot *rs = &rxring->slot[j];
		struct netmap_slot *ts = &txring->slot[k];
#ifdef NO_SWAP
		unsigned char *rxbuf = (unsigned char *)(NETMAP_BUF(rxring, rs->buf_idx));
		char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
/*		char *rxbuf = (char *)rxring + rxring->buf_ofs + (rs->buf_idx)*(rxring->nr_buf_size);
		char *txbuf = (char *)txring + txring->buf_ofs + (ts->buf_idx)*(txring->nr_buf_size);*/
#else
		uint32_t pkt;
#endif

		/* zhj: print rxbuf/txbuf
		for (i=0;i < rs->len;++i) {
            printf("%x", rxbuf[i]);
		}
		for (i=0;i < ts->len;++i) {
            printf("%x", txbuf[i]);
		}*/
/*		D("enter rs");
		D("%s", nm_dump_buf(rxbuf, rs->len, 128, NULL));
		D("change rs to ts");
		D("%s", nm_dump_buf(txbuf, ts->len, 128, NULL));*/
/*		unsigned char pkt_nm[8192];
		int i, pkt_len;
		pkt_len = strlen(nm_dump_buf(rxbuf, rs->len, 128, NULL));
		for (i=0; i < pkt_len; i++) {
            sprintf(pkt_nm + 3*i, "%02X ", (nm_dump_buf(rxbuf, rs->len, 128, NULL))[i]);
		}
		pkt_nm[3*i - 1] = '\0';
		printf("nm_dump_buf: [%s]\n", nm_dump_buf(rxbuf, rs->len, 128, NULL));
		strcpy(pkt_nm, nm_dump_buf(rxbuf, rs->len, 128, NULL));
		printf("pkt_nm: [%s]\n", nm_dump_buf(rxbuf, rs->len, 128, NULL));*/
/*		int pkt_len = sizeof(nm_dump_buf(rxbuf, ts->len, 128, NULL));
		pkt_nm = (unsigned char *)malloc(pkt_len * 8);*/
/*		memcpy(pkt_nm, nm_dump_buf(rxbuf, ts->len, 128, NULL), ts->len+1);
		pkt_nm = nm_dump_buf(rxbuf, ts->len, 128, NULL);*/
/*		unsigned long i;
		for (i=0; i< rs->len; i++) {
            printf("%02x ", rxbuf[i]);
		}*/


		/* zhj: extract eth packet */
		struct sw_flow_key key;
/*		key = (struct sw_flow_key *)malloc(sizeof(struct sw_flow_key *));*/
/*		int key_len = SW_FLOW_KEY_OFFSET(eth);*/
		memset(&key, 0, sizeof(key));

		memcpy(key.h.dl_dst, rxbuf, ETH_ALEN);
		memcpy(key.h.dl_src, rxbuf+6, ETH_ALEN);

		printf("src  %02x:%02x:%02x:%02x:%02x:%02x\n", key.h.dl_src[0], key.h.dl_src[1], key.h.dl_src[2], key.h.dl_src[3], key.h.dl_src[4], key.h.dl_src[5]);
		printf("dst  %02x:%02x:%02x:%02x:%02x:%02x\n", key.h.dl_dst[0], key.h.dl_dst[1], key.h.dl_dst[2], key.h.dl_dst[3], key.h.dl_dst[4], key.h.dl_dst[5]);
/*		printf("dst  0x%12x\n", key->eth.dst);*/


/*		memcpy(key->eth.type, rxbuf+12, 2);*/
		key.h.dl_type = *(u16 *)(rxbuf+12);
		printf("Eth Type: 0x%04x\n", key.h.dl_type);
		if (key.h.dl_type == htons(ETH_P_IP)) {
/*            key_len = SW_FLOW_KEY_OFFSET(ipv4.addr);*/
            key.h.nw_src = *(u32 *)(rxbuf+26);
/*            memcpy(&(key->ipv4.addr.src), rxbuf+26, 4);*/
            key.h.nw_dst = *(u32 *)(rxbuf+30);
            printf("IPv4 src: 0x%08x\n", key.h.nw_src);
            printf("IPv4 dst: 0x%08x\n", key.h.nw_dst);
            key.h.nw_proto = rxbuf[23];
            printf("IP Proto: %02x\n", key.h.nw_proto);
            key.h.nw_tos = rxbuf[15];
            printf("IP ToS:   %02x\n", key.h.nw_tos);
/*            key->ip.ttl = rxbuf[22];*/

            if (key.h.nw_proto == IPPROTO_ICMP) {
/*                    key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);*/
                    key.h.tp_src = htons(rxbuf[34]);/* ICMP Type */
                    key.h.tp_dst = htons(rxbuf[35]);/* ICMP Code */
                    printf("ICMP: 0x%04x 0x%04x\n", key.h.tp_src, key.h.tp_dst);
            }
            else if (key.h.nw_proto == IPPROTO_TCP) {
/*                    key_len = SW_FLOW_KEY_OFFSET(ipv4.tp);*/
                    key.h.tp_src = *(u16 *)(rxbuf+34);
                    key.h.tp_dst = *(u16 *)(rxbuf+36);
                    printf("TCP: 0x%04x 0x%04x\n", key.h.tp_src, key.h.tp_dst);
            }
		}

		key.hash_v = jhash2(&(key.h), 10, 0);


		/* match */
		static int c = 0;
		for(int i=0;i<ENTRY_NUM;++i){
            if(t.entry[i].hash_v == key.hash_v){
                printf("[matched] i:%d c:%d hash:%u\n", i, c, key.hash_v);
                actions(t.entry[i].actions, rxbuf, dst);
                break;
            }
            else
                printf("<not matched> i:%d c:%d thash:%u khash:%u\n", i, c, t.entry[i].hash_v, key.hash_v);
		}
		++c;
/*		printf("\n table  ");
 		printH(&(t.entry[0].header));
        printf("\n\n key    ");
        printH(&(key.h));
        printf("\n\n");*/


/*		free(key);*/

/*
            memcpy(key->ipv4.addr.dst, rxbuf+30, 4);
            memcpy(key->ip.proto, rxbuf+23, 1);
            memcpy(key->ip.tos, rxbuf+15, 1);
            memcpy(key->ip.ttl, rxbuf+22, 1);
            * todo: frag offset *
            printf("%02x %02x %02x %02x %02x %02x \n", key->eth.dst[0], key->eth.dst[1], key->eth.dst[2], key->eth.dst[3], key->eth.dst[4], key->eth.dst[5]);
*/
            /* if (key->ip.proto == IPPROTO_TCP) *
		}*/

		/* swap packets */
		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			D("wrong index rx[%d] = %d  -> tx[%d] = %d",
				j, rs->buf_idx, k, ts->buf_idx);
			sleep(2);
		}
#ifndef NO_SWAP
		pkt = ts->buf_idx;
		ts->buf_idx = rs->buf_idx;
		rs->buf_idx = pkt;
#endif
		/* copy the packet length. */
		if (rs->len < 14 || rs->len > 2048)
			D("wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
		else if (verbose > 1)
			D("%s send len %d rx[%d] -> tx[%d]", msg, rs->len, j, k);
		ts->len = rs->len;
/*		D("current ts-len: %d on rx[%d] -> tx[%d]", ts->len, j, k); zhangjie */
#ifdef NO_SWAP
		pkt_copy(rxbuf, txbuf, ts->len);
#else
		/* report the buffer change. */
		ts->flags |= NS_BUF_CHANGED;
		rs->flags |= NS_BUF_CHANGED;
#endif /* NO_SWAP */
		j = NETMAP_RING_NEXT(rxring, j);
		k = NETMAP_RING_NEXT(txring, k);
	}
	rxring->avail -= m;
	txring->avail -= m;
	rxring->cur = j;
	txring->cur = k;
	if (verbose && m > 0)
		D("%s sent %d packets to %p", msg, m, txring);

	return (m);
}

/* move packts from src to destination */
static int
move(struct my_ring *src, struct my_ring *dst, u_int limit, Flow_Table t)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, si = src->begin, di = dst->begin;
	printf("Qid %x %x\n", src->queueid, dst->queueid);/* zhj */
	printf("if %x %x\n", src->ifname, dst->ifname);/* zhj */
	const char *msg = (src->queueid & NETMAP_SW_RING) ?
		"host->net" : "net->host";

	while (si < src->end && di < dst->end) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		ND("txring %p rxring %p", txring, rxring);
		if (rxring->avail == 0) {
			si++;
			continue;
		}
		if (txring->avail == 0) {
			di++;
			continue;
		}
		m += process_rings(rxring, txring, limit, msg, t, dst);
	}

	return (m);
}

/*
 * how many packets on this set of queues ?
 */
static int
pkt_queued(struct my_ring *me, int tx)
{
	u_int i, tot = 0;

	ND("me %p begin %d end %d", me, me->begin, me->end);
	for (i = me->begin; i < me->end; i++) {
		struct netmap_ring *ring = tx ?
			NETMAP_TXRING(me->nifp, i) : NETMAP_RXRING(me->nifp, i);
		tot += ring->avail;
	}
	if (0 && verbose && tot && !tx)
		D("ring %s %s %s has %d avail at %d",
			me->ifname, tx ? "tx": "rx",
			me->end >= me->nifp->ni_tx_rings ? // XXX who comes first ?
				"host":"net",
			tot, NETMAP_TXRING(me->nifp, me->begin)->cur);
	return tot;
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: bridge [-v] [-i ifa] [-i ifb] [-b burst] [-w wait_time] [iface]\n");
	exit(1);
}

/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 * two intefaces.
 */
int
main(int argc, char **argv)
{
    /* for test: a flow table */
	Flow_Table fl;
	memset(&fl, 0, sizeof(fl));
	/*fl.entry[0].header.dl_src = {(u8)0x00,(u8)0x50,(u8)0x56,(u8)0x98,(u8)0x2d,(u8)0xef};*/
/*	unhexify("005056982def", fl.entry[0].header.dl_src);*/
	fl.entry[0].header.dl_src[0] = 0x00;
	fl.entry[0].header.dl_src[1] = 0x50;
	fl.entry[0].header.dl_src[2] = 0x56;
	fl.entry[0].header.dl_src[3] = 0x98;
	fl.entry[0].header.dl_src[4] = 0x82;
	fl.entry[0].header.dl_src[5] = 0x3f;
	unhexify("005056982def", fl.entry[0].header.dl_dst);
	fl.entry[0].header.dl_type = 0x0008;
	fl.entry[0].header.nw_src = 0x0c01a8c0;
	fl.entry[0].header.nw_dst = 0x0d01a8c0;
	fl.entry[0].header.nw_proto = 0x01;
	fl.entry[0].header.nw_tos = 0x00;
	fl.entry[0].header.tp_src = 0x0800;
	fl.entry[0].header.tp_dst = 0x0000;
	fl.entry[0].hash_v = jhash2(&(fl.entry[0].header), 10, 0);
	fl.entry[0].actions = 1;

	unhexify("00505698823f", fl.entry[1].header.dl_src);
	unhexify("005056982def", fl.entry[1].header.dl_dst);
	fl.entry[1].header.dl_type = 0x0008;
	fl.entry[1].header.nw_src = 0x0c01a8c0;
	fl.entry[1].header.nw_dst = 0x0d01a8c0;
	fl.entry[1].header.nw_proto = 0x06;
	fl.entry[1].header.tp_src = 0x4ec5;
	fl.entry[1].header.tp_dst = 0x1600;
	fl.entry[1].hash_v = jhash2(&(fl.entry[1].header), 10, 0);



/*	printf("FTsrc  %02x:%02x:%02x:%02x:%02x:%02x \n", fl.entry[0].header.dl_src[0], fl.entry[0].header.dl_src[1],
        fl.entry[0].header.dl_src[2], fl.entry[0].header.dl_src[3], fl.entry[0].header.dl_src[4], fl.entry[0].header.dl_src[5]);
    printf("FTdst  %02x:%02x:%02x:%02x:%02x:%02x \n", fl.entry[0].header.dl_dst[0], fl.entry[0].header.dl_dst[1],
        fl.entry[0].header.dl_dst[2], fl.entry[0].header.dl_dst[3], fl.entry[0].header.dl_dst[4], fl.entry[0].header.dl_dst[5]);
    printf("FT Eth Type: 0x%04x\n", fl.entry[0].header.dl_type);
    printf("FTv4 src: 0x%08x\n", fl.entry[0].header.nw_src);
    printf("FTv4 dst: 0x%08x\n", fl.entry[0].header.nw_dst);
    printf("FTIPProto: %02x\n", fl.entry[0].header.nw_proto);
    printf("FT IP ToS: %02x\n", fl.entry[0].header.nw_tos);
    printf("FT ICMP: 0x%04x 0x%04x\n", fl.entry[0].header.tp_src, fl.entry[0].header.tp_dst);*/

	struct pollfd pollfd[2];
	int i, ch;
	u_int burst = 1024, wait_link = 4;
	struct my_ring me[3];
	char *ifa = NULL, *ifb = NULL, *ifc = NULL;

	fprintf(stderr, "%s %s built %s %s\n",
		argv[0], version, __DATE__, __TIME__);

	bzero(me, sizeof(me));

	while ( (ch = getopt(argc, argv, "b:i:vw:")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'b':	/* burst */
			burst = atoi(optarg);
			break;
		case 'i':	/* interface */
			if (ifa == NULL)
				ifa = optarg;
			else if (ifb == NULL)
				ifb = optarg;
            else if (ifc == NULL)
                ifc = optarg;
			else
				D("%s ignored, already have 2 interfaces",
					optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			wait_link = atoi(optarg);
			break;
		}

	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		ifa = argv[1];
	if (argc > 2)
		ifb = argv[2];
    if (argc > 3)
		ifc = argv[3];
	if (argc > 4)
		burst = atoi(argv[4]);
    if (!ifc)
		ifc = ifa;
	if (!ifb)
		ifb = ifa;
	if (!ifa) {
		D("missing interface");
		usage();
	}
	if (burst < 1 || burst > 8192) {
		D("invalid burst %d, set to 1024", burst);
		burst = 1024;
	}
	if (wait_link > 100) {
		D("invalid wait_link %d, set to 4", wait_link);
		wait_link = 4;
	}
	/* setup netmap interface #1. */
	me[0].ifname = ifa;
	me[1].ifname = ifb;
	me[2].ifname = ifc;
	if (!strcmp(ifa, ifb)) {
		D("same interface, endpoint 0 goes to host");
		i = NETMAP_SW_RING;
	} else {
		/* two different interfaces. Take all rings on if1 */
		i = 0;	// all hw rings
	}
/*	if (netmap_open(me, i, 1))*/
	if (netmap_open(me, i, 1))
		return (1);
	me[2].mem = me[1].mem = me[0].mem; /* copy the pointer, so only one mmap */
	if (netmap_open(me+1, 0, 1))
		return (1);
    if (netmap_open(me+2, 0, 1))
		return (1);

	/* setup poll(2) variables. */
	memset(pollfd, 0, sizeof(pollfd));
	for (i = 0; i < 3; i++) {
		pollfd[i].fd = me[i].fd;
		pollfd[i].events = (POLLIN);
	}

	D("Wait %d secs for link to come up...", wait_link);
	sleep(wait_link);
	D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d <-> %s 0x%x/%d.",
		me[0].ifname, me[0].queueid, me[0].nifp->ni_rx_rings,
		me[1].ifname, me[1].queueid, me[1].nifp->ni_rx_rings
		me[2].ifname, me[2].queueid, me[2].nifp->ni_rx_rings);

	/* main loop */
	signal(SIGINT, sigint_h);
	while (!do_abort) {
		int n0, n1, ret;
		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;
		n0 = pkt_queued(me, 0);
		n1 = pkt_queued(me + 1, 0);
		if (n0)
			pollfd[1].events |= POLLOUT;
		else
			pollfd[0].events |= POLLIN;
		if (n1)
			pollfd[0].events |= POLLOUT;
		else
			pollfd[1].events |= POLLIN;
		ret = poll(pollfd, 2, 2500);
		if (ret <= 0 || verbose)
		    D("poll %s [0] ev %x %x rx %d@%d tx %d,"
			     " [1] ev %x %x rx %d@%d tx %d",
				ret <= 0 ? "timeout" : "ok",
				pollfd[0].events,
				pollfd[0].revents,
				pkt_queued(me, 0),
				me[0].rx->cur,
				pkt_queued(me, 1),
				pollfd[1].events,
				pollfd[1].revents,
				pkt_queued(me+1, 0),
				me[1].rx->cur,
				pkt_queued(me+1, 1)
			);
		if (ret < 0)
			continue;
		if (pollfd[0].revents & POLLERR) {
			D("error on fd0, rxcur %d@%d",
				me[0].rx->avail, me[0].rx->cur);
		}
		if (pollfd[1].revents & POLLERR) {
			D("error on fd1, rxcur %d@%d",
				me[1].rx->avail, me[1].rx->cur);
		}
		if (pollfd[0].revents & POLLOUT) {
			move(me + 1, me, burst, fl);
			// XXX we don't need the ioctl */
			// ioctl(me[0].fd, NIOCTXSYNC, NULL);
		}
		if (pollfd[1].revents & POLLOUT) {
			move(me, me + 1, burst, fl);
			// XXX we don't need the ioctl */
			// ioctl(me[1].fd, NIOCTXSYNC, NULL);
		}
	}
	D("exiting");
	netmap_close(me + 1);
	netmap_close(me + 0);

	return (0);
}

#ifndef OF_ZJ_H
#define OF_ZJ_H 1

#include "nm_util.h"
#include "openflow-1.0.0.h"
/* #include <stdint.h> */
#include <string.h>
#include <stddef.h>

#ifdef __CHECKER__
#define __CHECK_ENDIAN__
#endif

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#endif

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#define SW_FLOW_KEY_OFFSET(field)		\
	(offsetof(struct sw_flow_key, field) +	\
	 FIELD_SIZEOF(struct sw_flow_key, field))

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint16_t __bitwise__ __be16;
typedef uint32_t __bitwise__ __be32;
typedef uint64_t __bitwise__ __be64;

#define ENTRY_NUM 3

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef __rcu
#define __rcu
#endif



#ifndef __LINUX_SPINLOCK_TYPES_UP_H
#define __LINUX_SPINLOCK_TYPES_UP_H

/*
#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif*/
/*
 * include/linux/spinlock_types_up.h - spinlock type definitions for UP
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

#ifdef CONFIG_DEBUG_SPINLOCK

typedef struct {
        volatile unsigned int slock;
} arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { 1 }

#else

typedef struct { } arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { }

#endif

typedef struct {
        /* no debug version on UP */
} arch_rwlock_t;

#define __ARCH_RW_LOCK_UNLOCKED { }

#endif /* __LINUX_SPINLOCK_TYPES_UP_H */

typedef struct raw_spinlock {
        arch_spinlock_t raw_lock;
#ifdef CONFIG_GENERIC_LOCKBREAK
        unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
        unsigned int magic, owner_cpu;
        void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
        struct lockdep_map dep_map;
#endif
} raw_spinlock_t;

typedef struct spinlock {
         union {
                 struct raw_spinlock rlock;

 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 # define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
                 struct {
                         u8 __padding[LOCK_PADSIZE];
                         struct lockdep_map dep_map;
                 };
 #endif
         };
 } spinlock_t;

/*
 * This file describes reciprocical division.
 *
 * This optimizes the (A/B) problem, when A and B are two u32
 * and B is a known value (but not known at compile time)
 *
 * The math principle used is :
 *   Let RECIPROCAL_VALUE(B) be (((1LL << 32) + (B - 1))/ B)
 *   Then A / B = (u32)(((u64)(A) * (R)) >> 32)
 *
 * This replaces a divide by a multiply (and a shift), and
 * is generally less expensive in CPU cycles.
 */

/*
 * Computes the reciprocal value (R) for the value B of the divisor.
 * Should not be called before each reciprocal_divide(),
 * or else the performance is slower than a normal divide.
 */


static inline u32 reciprocal_divide(u32 A, u32 R)
{
	return (u32)(((u64)A * R) >> 32);
}


struct hlist_node {
        struct hlist_node *next, **pprev;
};

/* Ethernet / IP / UDP header IPv4 */
const int udp_payload_offset = 42;/* 14+20+8 */

/* FreeBSD or Solaris */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
struct ethhdr {
        unsigned char     h_dest[ETH_ALEN];
        unsigned char     h_source[ETH_ALEN];
        u16               h_proto;
};
#endif

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

#ifdef USE_IPV6
struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};
#endif


struct hep_hdr{
    u8 hp_v;            /* version */
    u8 hp_l;            /* length */
    u8 hp_f;            /* family */
    u8 hp_p;            /* protocol */
    u16 hp_sport;       /* source port */
    u16 hp_dport;       /* destination port */
};

struct hep_timehdr{
    u32 tv_sec;         /* seconds */
    u32 tv_usec;        /* useconds */
    u16 captid;         /* Capture ID node */
};

/**
  * struct callback_head - callback structure for use with RCU and task_work
  * @next: next update requests in a list
  * @func: actual update function to call after the grace period.
  */
 struct callback_head {
         struct callback_head *next;
         void (*func)(struct callback_head *head);
 };
#ifndef rcu_head
#define rcu_head callback_head
#endif


/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose. It has no warranty.
 *
 * $FreeBSD: head/sys/dev/cxgbe/common/jhash.h 222509 2011-05-30 21:07:26Z np $
 */

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
{ \
 a -= b; a -= c; a ^= (c>>13); \
 b -= c; b -= a; b ^= (a<<8); \
 c -= a; c -= b; c ^= (b>>13); \
 a -= b; a -= c; a ^= (c>>12); \
 b -= c; b -= a; b ^= (a<<16); \
 c -= a; c -= b; c ^= (b>>5); \
 a -= b; a -= c; a ^= (c>>3); \
 b -= c; b -= a; b ^= (a<<10); \
 c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO 0x9e3779b9

/* The most generic version, hashes an arbitrary sequence
 * of bytes. No alignment or length assumptions are made about
 * the input key.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
 u32 a, b, c, len;
 const u8 *k = key;

 len = length;
 a = b = JHASH_GOLDEN_RATIO;
 c = initval;

 while (len >= 12) {
 a += (k[0] +((u32)k[1]<<8) +((u32)k[2]<<16) +((u32)k[3]<<24));
 b += (k[4] +((u32)k[5]<<8) +((u32)k[6]<<16) +((u32)k[7]<<24));
 c += (k[8] +((u32)k[9]<<8) +((u32)k[10]<<16)+((u32)k[11]<<24));

 __jhash_mix(a,b,c);

 k += 12;
 len -= 12;
 }

 c += length;
 switch (len) {
 case 11: c += ((u32)k[10]<<24);
 case 10: c += ((u32)k[9]<<16);
 case 9 : c += ((u32)k[8]<<8);
 case 8 : b += ((u32)k[7]<<24);
 case 7 : b += ((u32)k[6]<<16);
 case 6 : b += ((u32)k[5]<<8);
 case 5 : b += k[4];
 case 4 : a += ((u32)k[3]<<24);
 case 3 : a += ((u32)k[2]<<16);
 case 2 : a += ((u32)k[1]<<8);
 case 1 : a += k[0];
 };

 __jhash_mix(a,b,c);

 return c;
}

/* A special optimized version that handles 1 or more of u32s.
 * The length parameter here is the number of u32s in the key.
 */
static inline u32 jhash2(u32 *k, u32 length, u32 initval)
{
 u32 a, b, c, len;

 a = b = JHASH_GOLDEN_RATIO;
 c = initval;
 len = length;

 while (len >= 3) {
 a += k[0];
 b += k[1];
 c += k[2];
 __jhash_mix(a, b, c);
 k += 3; len -= 3;
 }

 c += length * 4;

 switch (len) {
 case 2 : b += k[1];
 case 1 : a += k[0];
 };

 __jhash_mix(a,b,c);

 return c;
}


/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 * done at the end is not done here.
 */
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
 a += JHASH_GOLDEN_RATIO;
 b += JHASH_GOLDEN_RATIO;
 c += initval;

 __jhash_mix(a, b, c);

 return c;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
 return jhash_3words(a, b, 0, initval);
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
 return jhash_3words(a, 0, 0, initval);
}





/**
 * enum ovs_frag_type - IPv4 and IPv6 fragment type
 * @OVS_FRAG_TYPE_NONE: Packet is not a fragment.
 * @OVS_FRAG_TYPE_FIRST: Packet is a fragment with offset 0.
 * @OVS_FRAG_TYPE_LATER: Packet is a fragment with nonzero offset.
 *
 * Used as the @ipv4_frag in &struct ovs_key_ipv4 and as @ipv6_frag &struct
 * ovs_key_ipv6.
 */
enum frag_type {
	FRAG_TYPE_NONE,
	FRAG_TYPE_FIRST,
	FRAG_TYPE_LATER,
	FRAG_TYPE_MAX
};

struct ovs_key_ipv4_tunnel {
	__be64 tun_id;
	__be32 ipv4_src;
	__be32 ipv4_dst;
	u16  tun_flags;
	u8   ipv4_tos;
	u8   ipv4_ttl;
};

/*
struct sw_flow_key {
	struct {
		union {
			struct ovs_key_ipv4_tunnel tun_key;  * Encapsulating tunnel key. *
		} tun;
		u32	priority;	* Packet QoS priority. *
		u32	skb_mark;	* SKB mark. *
		u16	in_port;	* Input switch port (or DP_MAX_PORTS). *
	} phy;
	struct {
		u8     src[ETH_ALEN];	* Ethernet source address. *
		u8     dst[ETH_ALEN];	* Ethernet destination address. *
		__be16 tci;		* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. *
		__be16 type;		* Ethernet frame type. *
	} eth;
	struct {
		u8     proto;		* IP protocol or lower 8 bits of ARP opcode. *
		u8     tos;		* IP ToS. *
		u8     ttl;		* IP TTL/hop limit. *
		u8     frag;		* One of OVS_FRAG_TYPE_*. *
	} ip;
	union {
		struct {
			struct {
				__be32 src;	* IP source address. *
				__be32 dst;	* IP destination address. *
			} addr;
			union {
				struct {
					__be16 src;		* TCP/UDP source port. *
					__be16 dst;		* TCP/UDP destination port. *
				} tp;
				struct {
					u8 sha[ETH_ALEN];	* ARP source hardware address. *
					u8 tha[ETH_ALEN];	* ARP target hardware address. *
				} arp;
			};
		} ipv4;
		struct {
			struct {
				struct in6_addr src;	* IPv6 source address. *
				struct in6_addr dst;	* IPv6 destination address. *
			} addr;
			__be32 label;			* IPv6 flow label. *
			struct {
				__be16 src;		* TCP/UDP source port. *
				__be16 dst;		* TCP/UDP destination port. *
			} tp;
			struct {
				struct in6_addr target;	* ND target address. *
				u8 sll[ETH_ALEN];	* ND source link layer address. *
				u8 tll[ETH_ALEN];	* ND target link layer address. *
			} nd;
		} ipv6;
	};
};*/
struct sw_flow_key {
    struct ofp_match h;
    u32 hash_v;
};


#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
        for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
        for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
             pos = n)

#define hlist_entry_safe(ptr, type, member) \
        ({ typeof(ptr) ____ptr = (ptr); \
           ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
        })

/**
 * hlist_for_each_entry_rcu - iterate over rcu list of given type
 * @pos:        the type * to use as a loop cursor.
 * @head:       the head for your list.
 * @member:     the name of the hlist_node within the struct.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as hlist_add_head_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#define hlist_for_each_entry_rcu(tpos, pos, head, member)               \
       for (pos = rcu_dereference_raw(hlist_first_rcu(head));          \
               pos &&                                                   \
               ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
               pos = rcu_dereference_raw(hlist_next_rcu(pos)))



#define FLEX_ARRAY_PART_SIZE PAGE_SIZE
#define FLEX_ARRAY_BASE_SIZE PAGE_SIZE

struct flex_array_part {
	char elements[FLEX_ARRAY_PART_SIZE];
};

/*
 * This is meant to replace cases where an array-like
 * structure has gotten too big to fit into kmalloc()
 * and the developer is getting tempted to use
 * vmalloc().
 */

struct flex_array {
	union {
		struct {
			int element_size;
			int total_nr_elements;
			int elems_per_part;
			u32 reciprocal_elems;
			struct flex_array_part *parts[];
		};
		/*
		 * This little trick makes sure that
		 * sizeof(flex_array) == PAGE_SIZE
		 */
		char padding[FLEX_ARRAY_BASE_SIZE];
	};
};

/* Number of bytes left in base struct flex_array, excluding metadata */
#define FLEX_ARRAY_BASE_BYTES_LEFT					\
	(FLEX_ARRAY_BASE_SIZE - offsetof(struct flex_array, parts))


/*
 * If a user requests an allocation which is small
 * enough, we may simply use the space in the
 * flex_array->parts[] array to store the user
 * data.
 */
static inline int elements_fit_in_base(struct flex_array *fa)
{
	int data_size = fa->element_size * fa->total_nr_elements;
	if ((unsigned long)data_size <= FLEX_ARRAY_BASE_BYTES_LEFT)
		return 1;
	return 0;
}

static int fa_element_to_part_nr(struct flex_array *fa,
					unsigned int element_nr)
{
	return reciprocal_divide(element_nr, fa->reciprocal_elems);
}

static unsigned int index_inside_part(struct flex_array *fa,
					unsigned int element_nr,
					unsigned int part_nr)
{
	unsigned int part_offset;

	part_offset = element_nr - part_nr * fa->elems_per_part;
	return part_offset * fa->element_size;
}

/**
 * flex_array_get - pull data back out of the array
 * @fa:		the flex array from which to extract data
 * @element_nr:	index of the element to fetch from the array
 *
 * Returns a pointer to the data at index @element_nr.  Note
 * that this is a copy of the data that was passed in.  If you
 * are using this to store pointers, you'll get back &ptr.  You
 * may instead wish to use the flex_array_get_ptr helper.
 *
 * Locking must be provided by the caller.
 */
void *flex_array_get(struct flex_array *fa, unsigned int element_nr)
{
	int part_nr = 0;
	struct flex_array_part *part;

	if (!fa->element_size)
		return NULL;
	if (element_nr >= (unsigned int)(fa->total_nr_elements))
		return NULL;
	if (elements_fit_in_base(fa))
		part = (struct flex_array_part *)&fa->parts[0];
	else {
		part_nr = fa_element_to_part_nr(fa, element_nr);
		part = fa->parts[part_nr];
		if (!part)
			return NULL;
	}
	return &part->elements[index_inside_part(fa, element_nr, part_nr)];
}

/**
 * flex_array_get_ptr - pull a ptr back out of the array
 * @fa:		the flex array from which to extract data
 * @element_nr:	index of the element to fetch from the array
 *
 * Returns the pointer placed in the flex array at element_nr using
 * flex_array_put_ptr().  This function should not be called if the
 * element in question was not set using the _put_ptr() helper.
 */
void *flex_array_get_ptr(struct flex_array *fa, unsigned int element_nr)
{
	void **tmp;

	tmp = flex_array_get(fa, element_nr);
	if (!tmp)
		return NULL;

	return *tmp;
}

struct nlattr {
    u16 nla_len;
    u16 nla_type;
};

struct sw_flow_actions {
	struct rcu_head rcu;
	u32 actions_len;
	struct nlattr actions[];
};

/* struct flow_table {
	struct flex_array *buckets;
	unsigned int count, n_buckets;
	struct rcu_head rcu;
	int node_ver;
	u32 hash_seed;
	_Bool keep_flows;
}; */

/*
struct sw_flow {
	struct rcu_head rcu;
	struct hlist_node hash_node[2];
	u32 hash;

	struct sw_flow_key key;
	struct sw_flow_actions __rcu *sf_acts;

	spinlock_t lock;	* Lock for values below. *
	unsigned long used;	* Last used time (in jiffies). *
	u64 packet_count;	* Number of packets matched. *
	u64 byte_count;		* Number of bytes matched. *
	u8 tcp_flags;		* Union of seen TCP flags. *
};*/
/*
static u32 ovs_flow_hash(const struct sw_flow_key *key, int key_start, int key_len)
{
	return jhash2((u32 *)((u8 *)key + key_start),
		      DIV_ROUND_UP(key_len - key_start, sizeof(u32)), 0);
}*/

/*
static int flow_key_start(struct sw_flow_key *key)
{
	if (key->phy.tun.tun_key.ipv4_dst)
		return 0;
	else
		return offsetof(struct sw_flow_key, phy.priority);
}*/

/*
static struct hlist_head *find_bucket(struct flow_table *table, u32 hash)
{
	hash = jhash_1word(hash, table->hash_seed);
	return flex_array_get(table->buckets,
				(hash & (table->n_buckets - 1)));
}*/


/* for test: flow table entry */
typedef struct flow_entry {

    struct ofp_match header;
    unsigned int counters;
    int actions;
    u32 hash_v;

} Flow_Entry;

typedef struct flow_table {

    Flow_Entry entry[ENTRY_NUM];

} Flow_Table;


#endif // OF_ZJ_H

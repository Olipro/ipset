/* Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define CONCAT(a, b, c)		a##b##c
#define TOKEN(a, b, c)		CONCAT(a, b, c)

/* IPv4/IPv6 dependent function prototypes for hash:ip */

#if PF == 4
#define HOST_MASK	32
#define NLA_PUT_ADDR(skb, ip) \
	NLA_PUT_NET32(skb, IPSET_ATTR_IP, *(ip));
#else
#define HOST_MASK	128
#define NLA_PUT_ADDR(skb, ip) \
	NLA_PUT(skb, IPSET_ATTR_IP, sizeof(struct in6_addr), ip);
#endif

#define hash_ip_pf_timeout	TOKEN(hash_ip, PF, _timeout)
#define hash_ip_pf_expired	TOKEN(hash_ip, PF, _expired)
#define hash_ip_pf_elem_test	TOKEN(hash_ip, PF, _elem_test)
#define hash_ip_pf_elem_exist	TOKEN(hash_ip, PF, _elem_exist)
#define hash_ip_pf_elem_expired	TOKEN(hash_ip, PF, _elem_expired)
#define hash_ip_pf_test		TOKEN(hash_ip, PF, _test)
#define hash_ip_pf_add		TOKEN(hash_ip, PF, _add)
#define hash_ip_pf_readd	TOKEN(hash_ip, PF, _readd)
#define hash_ip_pf_del		TOKEN(hash_ip, PF, _del)
#define hash_ip_pf_map_expired	TOKEN(hash_ip, PF, _map_expired)
#define hash_ip_pf_set_expired	TOKEN(hash_ip, PF, _set_expired)
#define hash_ip_pf_head		TOKEN(hash_ip, PF, _head)
#define hash_ip_pf_list		TOKEN(hash_ip, PF, _list)
#define hash_ip_pf_resize	TOKEN(hash_ip, PF, _resize)
#define hash_ip_pf		TOKEN(hash_ip, PF , )
#define hash_ip_pf_kadt		TOKEN(hash_ip, PF, _kadt)
#define hash_ip_pf_uadt		TOKEN(hash_ip, PF, _uadt)
#define hash_ip_pf_destroy	TOKEN(hash_ip, PF, _destroy)
#define hash_ip_pf_flush	TOKEN(hash_ip, PF, _flush)
#define hash_ip_pf_timeout_gc	TOKEN(hash_ip, PF, _timeout_gc)
#define hash_ip_pf_gc_init	TOKEN(hash_ip, PF, _gc_init)
#define ip_pf_hash		TOKEN(ip, PF, _hash)
#define ip_pf_cmp		TOKEN(ip, PF, _cmp)
#define ip_pf_null		TOKEN(ip, PF, _null)
#define ip_pf_cpy		TOKEN(ip, PF, _cpy)
#define ip_pf_zero_out		TOKEN(ip, PF, _zero_out)
#define ip_pf_elem		TOKEN(ip, PF, _elem)
#define ip_pf_elem_timeout	TOKEN(ip, PF, _elem_timeout)
#define ip_pf_get_elem_timeout	TOKEN(get_ip, PF, _elem_timeout)

static inline bool
hash_ip_pf_timeout(const struct hash_ip *map, uint32_t id)
{
	struct ip_pf_elem_timeout *elem = hash_ip_elem(map, id);

	return ip_set_timeout_test(elem->timeout);
}

static inline bool
hash_ip_pf_expired(const struct hash_ip *map, uint32_t id)
{
	struct ip_pf_elem_timeout *elem = hash_ip_elem(map, id);

	return ip_set_timeout_expired(elem->timeout);
}

static inline bool
hash_ip_pf_elem_test(const struct hash_ip *map, bool with_timeout,
		     uint32_t id, struct ip_pf_elem * ip)
{
	struct ip_pf_elem *elem = hash_ip_elem(map, id);

	return ip_pf_cmp(elem, ip)
		&& (!with_timeout || hash_ip_pf_timeout(map, id));
}

static inline bool
hash_ip_pf_elem_exist(const struct hash_ip *map, bool with_timeout,
		      uint32_t id)
{
	struct ip_pf_elem *elem = hash_ip_elem(map, id);

	return !(ip_pf_null(elem)
		 || (with_timeout && hash_ip_pf_expired(map, id)));
}

static inline bool
hash_ip_pf_elem_expired(const struct hash_ip *map, bool with_timeout,
			uint32_t id)
{
	struct ip_pf_elem *elem = hash_ip_elem(map, id);

	return ip_pf_null(elem)
	       || (with_timeout && hash_ip_pf_expired(map, id));
}

static inline uint32_t
hash_ip_pf_test(const struct hash_ip *map, bool with_timeout,
		struct ip_pf_elem * ip)
{
	uint32_t id;
	uint8_t i;

	for (i = 0; i < map->probes; i++) {
		id = ip_pf_hash(ip, *(map->initval + i), map->hashsize);
		if (hash_ip_pf_elem_test(map, with_timeout, id, ip))
			return id + 1;
		/* No shortcut - there can be deleted entries. */
	}
	return 0;
}

static void
hash_ip_pf_map_expired(struct hash_ip *map)
{
	struct ip_pf_elem_timeout *table = map->members;
	uint32_t i;

	/* We run parallel with other readers (test element)
	 * but adding/deleting new entries is locked out */
	for (i = 0; i < map->hashsize; i++)
		if (ip_set_timeout_expired(table[i].timeout)) {
		    	ip_pf_zero_out((struct ip_pf_elem *)&table[i]);
		    	table[i].timeout = IPSET_ELEM_UNSET;
		    	map->elements--;
		}
}

static inline void
hash_ip_pf_set_expired(struct ip_set *set)
{
	/* We run parallel with other readers (test element)
	 * but adding/deleting new entries is locked out */
	read_lock_bh(&set->lock);
	hash_ip_pf_map_expired(set->data);
	read_unlock_bh(&set->lock);
}

static int
hash_ip_pf_add(struct hash_ip *map, bool with_timeout,
	       struct ip_pf_elem *ip, uint32_t timeout)
{
	uint32_t id, empty = 0;
	uint8_t i;
	
	if (map->elements >= map->maxelem) {
		if (with_timeout) {
			hash_ip_pf_map_expired(map);
			if (map->elements < map->maxelem)
				goto doit;
		}
		return -IPSET_ERR_HASH_FULL;
	}

doit:
	for (i = 0; i < map->probes; i++) {
		id = ip_pf_hash(ip, *(map->initval + i), map->hashsize);
		if (hash_ip_pf_elem_test(map, with_timeout, id, ip))
			return -IPSET_ERR_EXIST;	
		if (empty == 0
		    && hash_ip_pf_elem_expired(map, with_timeout, id))
			empty = id + 1;
		/* There can be deleted entries, must check all slots */
	}
	if (!empty)
		/* Trigger rehashing */
		return -EAGAIN;

	if (with_timeout) {
		struct ip_pf_elem_timeout *e = hash_ip_elem(map, empty - 1);
		e->timeout = ip_set_timeout_set(timeout);
		D("add with timeout: %u (%lu)", timeout, e->timeout);
		ip_pf_cpy((struct ip_pf_elem *)e, ip); 
	} else {
		struct ip_pf_elem *e = hash_ip_elem(map, empty - 1);
		ip_pf_cpy(e, ip);
	}
	map->elements++;
	return 0;
}

static int
hash_ip_pf_readd(struct hash_ip *map, bool with_timeout, struct ip_pf_elem *ip)
{
	uint32_t id, empty = 0;
	uint8_t i;
	
	for (i = 0; empty == 0 && i < map->probes; i++) {
		id = ip_pf_hash(ip, *(map->initval + i), map->hashsize);
		if (ip_pf_null(hash_ip_elem(map, id)))
			empty = id + 1;
	}
	if (!empty)
		/* Trigger rehashing */
		return -EAGAIN;

	if (with_timeout) {
		struct ip_pf_elem_timeout *e = hash_ip_elem(map, empty - 1);
		e->timeout = ip_pf_get_elem_timeout(ip);
		ip_pf_cpy((struct ip_pf_elem *)e, ip); 
	} else {
		struct ip_pf_elem *e = hash_ip_elem(map, empty - 1);
		ip_pf_cpy(e, ip);
	}
	map->elements++;
	return 0;
}

static int
hash_ip_pf_del(struct hash_ip *map, bool with_timeout, struct ip_pf_elem *ip)
{
	struct ip_pf_elem *e;
	uint32_t id, found = 0;
	uint8_t i;

	for (i = 0; i < map->probes; i++) {
		id = ip_pf_hash(ip, *(map->initval + i), map->hashsize);
		if (hash_ip_pf_elem_test(map, with_timeout, id, ip)) {
			found = id + 1;
			break;
		}
	}
	if (!found)
		return -IPSET_ERR_EXIST;
		
	e = hash_ip_elem(map, found - 1);
	ip_pf_zero_out(e);
	if (with_timeout)
		((struct ip_pf_elem_timeout *)e)->timeout = IPSET_ELEM_UNSET;

	map->elements--;

	return 0;
}

static int
hash_ip_pf_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct hash_ip *map = set->data;
	struct nlattr *nested;
	
	if (set->flags & IP_SET_FLAG_TIMEOUT)
		hash_ip_pf_set_expired(set);

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT_NET32(skb, IPSET_ATTR_HASHSIZE, htonl(map->hashsize));
	NLA_PUT_NET32(skb, IPSET_ATTR_MAXELEM, htonl(map->maxelem));
	if (map->netmask != HOST_MASK)
		NLA_PUT_U8(skb, IPSET_ATTR_NETMASK, map->netmask);
	NLA_PUT_U8(skb, IPSET_ATTR_PROBES, map->probes);
	NLA_PUT_U8(skb, IPSET_ATTR_RESIZE, map->resize);
	NLA_PUT_NET32(skb, IPSET_ATTR_ELEMENTS, htonl(map->elements));
	NLA_PUT_NET32(skb, IPSET_ATTR_REFERENCES,
		      htonl(atomic_read(&set->ref) - 1));
	NLA_PUT_NET32(skb, IPSET_ATTR_MEMSIZE,
		      htonl(map->hashsize * map->elem_size));
	if (set->flags & IP_SET_FLAG_TIMEOUT)
		NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT, htonl(map->timeout));
	ipset_nest_end(skb, nested);
	
	return 0;
nla_put_failure:
	return -EFAULT;
}

static int
hash_ip_pf_list(struct ip_set *set,
		struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct hash_ip *map = set->data;
	struct nlattr *atd, *nested;
	struct ip_pf_elem *elem;
	uint32_t id, first = cb->args[2];
	bool with_timeout = set->flags & IP_SET_FLAG_TIMEOUT;

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EFAULT;
	for (; cb->args[2] < map->hashsize; cb->args[2]++) {
		id = cb->args[2];
		if (hash_ip_pf_elem_expired(map, with_timeout, id))
			continue;
		nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
		if (!nested) {
			if (id == first) {
				nla_nest_cancel(skb, atd);
				return -EFAULT;
			} else
				goto nla_put_failure;
		}
		elem = hash_ip_elem(map, id);
		NLA_PUT_ADDR(skb, &elem->ip);
		if (map->netmask != HOST_MASK)
			NLA_PUT_U8(skb, IPSET_ATTR_CIDR, map->netmask);
		if (with_timeout) {
			unsigned long timeout = ip_pf_get_elem_timeout(elem);
			D("list with timeout: %u (%lu)",
			  ip_set_timeout_get(timeout), timeout);
			NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT,
				      htonl(ip_set_timeout_get(timeout)));
		}
		ipset_nest_end(skb, nested);
	}
	ipset_nest_end(skb, atd);
	/* Set listing finished */
	cb->args[2] = 0;
	
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nested);
	ipset_nest_end(skb, atd);
	return 0;
}

static int
hash_ip_pf_resize(struct ip_set *set, uint8_t retried)
{
	struct hash_ip *map = set->data, *tmp;
	void *members;
	uint32_t i, hashsize = map->hashsize;
	uint8_t oflags, flags = set->flags;
	bool with_timeout = flags & IP_SET_FLAG_TIMEOUT;
	int ret;
	
	if (map->resize == 0)
		return -IPSET_ERR_HASH_FULL;

	/* Try to cleanup first */
	if (retried == 0 && with_timeout) {
		i = map->elements;
		hash_ip_pf_set_expired(set);
		if (map->elements < i)
			return 0;
	}

again:
	ret = 0;
	
	/* Calculate new hash size */
	hashsize += (hashsize * map->resize)/100;
	if (hashsize == map->hashsize)
		hashsize++;
	if (hashsize >= map->maxelem)
		return -IPSET_ERR_HASH_FULL;
	
	printk("Rehashing of set %s triggered: hash grows from %lu to %lu\n",
	       set->name,
	       (long unsigned)map->hashsize,
	       (long unsigned)hashsize);

	tmp = kmalloc(sizeof(struct hash_ip)
		      + map->probes * sizeof(initval_t), GFP_ATOMIC);
	if (!tmp)
		return -ENOMEM;

	memcpy(tmp, map, sizeof(*map) + map->probes * sizeof(initval_t));
	tmp->elements = 0;
	tmp->hashsize = hashsize;
	tmp->members = ip_set_alloc(hashsize * map->elem_size,
				    GFP_ATOMIC, &flags);
	if (!tmp->members) {
		kfree(tmp);
		return -ENOMEM;
	}
	
	write_lock_bh(&set->lock);
	map = set->data; /* Play safe */
	for (i = 0; i < map->hashsize && ret == 0; i++) {
		if (hash_ip_pf_elem_exist(map, with_timeout, i))
			ret = hash_ip_pf_readd(tmp, with_timeout,
					       hash_ip_elem(map, i));
	}
	if (ret) {
		/* Failure, try again */
		write_unlock_bh(&set->lock);
		ip_set_free(tmp->members, flags);
		kfree(tmp);
		goto again;
	}
	
	/* Success at resizing! */
	members = map->members;
	oflags = set->flags;
	
	map->hashsize = tmp->hashsize;
	map->members = tmp->members;
	map->elements = tmp->elements;
	set->flags = flags;
	write_unlock_bh(&set->lock);
	
	ip_set_free(members, oflags);
	kfree(tmp);
	
	return 0;
}

static int
hash_ip_pf_kadt(struct ip_set *set, const struct sk_buff * skb,
		enum ipset_adt adt, uint8_t pf, const uint8_t *flags);
static int
hash_ip_pf_uadt(struct ip_set *set, struct nlattr *head, int len,
		enum ipset_adt adt, uint32_t *lineno, uint32_t flags);

static const struct ip_set_type_variant hash_ip_pf __read_mostly = {
	.kadt	= hash_ip_pf_kadt,
	.uadt	= hash_ip_pf_uadt,
	.destroy = hash_ip_pf_destroy,
	.flush	= hash_ip_pf_flush,
	.head	= hash_ip_pf_head,
	.list	= hash_ip_pf_list,
	.resize	= hash_ip_pf_resize,
};

static void
hash_ip_pf_timeout_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct hash_ip *map = set->data;

	hash_ip_pf_set_expired(set);

	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}

static inline void
hash_ip_pf_gc_init(struct ip_set *set)
{
	struct hash_ip *map = set->data;
	
	init_timer(&map->gc);
	map->gc.data = (unsigned long) set;
	map->gc.function = hash_ip_pf_timeout_gc;
	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}

#undef HOST_MASK
#undef NLA_PUT_ADDR
#undef hash_ip_pf_timeout
#undef hash_ip_pf_expired
#undef hash_ip_pf_elem_test
#undef hash_ip_pf_elem_exist
#undef hash_ip_pf_elem_expired
#undef hash_ip_pf_test
#undef hash_ip_pf_add
#undef hash_ip_pf_readd
#undef hash_ip_pf_del
#undef hash_ip_pf_map_expired
#undef hash_ip_pf_set_expired
#undef hash_ip_pf_head
#undef hash_ip_pf_list
#undef hash_ip_pf_resize
#undef hash_ip_pf
#undef hash_ip_pf_kadt
#undef hash_ip_pf_uadt
#undef hash_ip_pf_destroy
#undef hash_ip_pf_flush
#undef hash_ip_pf_timeout_gc
#undef hash_ip_pf_gc_init
#undef ip_pf_hash
#undef ip_pf_cmp
#undef ip_pf_null
#undef ip_pf_cpy
#undef ip_pf_zero_out
#undef ip_pf_elem
#undef ip_pf_elem_timeout
#undef ip_pf_get_elem_timeout

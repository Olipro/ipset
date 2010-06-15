#ifndef _IP_SET_CHASH_H
#define _IP_SET_CHASH_H

#include <linux/netfilter/ip_set_jhash.h>
#include <linux/netfilter/ip_set_slist.h>
#include <linux/netfilter/ip_set_timeout.h>

#define CONCAT(a, b, c)		a##b##c
#define TOKEN(a, b, c)		CONCAT(a, b, c)

/* Cache friendly hash with resizing when linear searching becomes too long.
 * Internally jhash is used with the assumption that the size of the stored
 * data is a multiple of sizeof(u32). If storage supports timeout, the
 * timeout field must be the last one in the data structure.
 */
   
/* Number of elements to store in an array block */
#define CHASH_DEFAULT_ARRAY_SIZE        4
/* Number of arrays: max ARRAY_SIZE * CHAIN_LIMIT "long" chains */
#define CHASH_DEFAULT_CHAIN_LIMIT       3

struct chash_nets {
	u32 nets;		/* number of elements per cidr */
	u8 cidr;		/* the cidr values added to the set */
};

struct chash {
	struct slist *htable;	/* Hashtable of single linked lists */
	u32 maxelem;		/* Max elements in the hash */
	u32 elements;		/* Current element (vs timeout) */
	u32 initval;		/* random jhash init value */
	u32 timeout;		/* timeout value, if enabled */
	struct timer_list gc;	/* garbage collection when timeout enabled */
	u8 htable_bits;		/* size of hash table == 2^htable_bits */
	u8 array_size;		/* number of elements in an array */
	u8 chain_limit;		/* max number of arrays */
#ifdef IP_SET_HASH_WITH_NETMASK
	u8 netmask;		/* netmask value for subnets to store */
#endif
#ifdef IP_SET_HASH_WITH_NETS
	struct chash_nets nets[0]; /* book keeping of networks */
#endif
};

static inline u8
htable_bits(u32 hashsize)
{
	/* Assume that hashsize == 2^htable_bits */
	u8 bits = fls(hashsize - 1);
	if (jhash_size(bits) != hashsize)
		/* Round up to the first 2^n value */
		bits = fls(hashsize);

	return bits;
}

static inline void
add_cidr(struct chash_nets *nets, u8 host_mask, u8 cidr)
{
	u8 i;

	pr_debug("add_cidr %u", cidr);
	for (i = 0; i < host_mask - 1 && nets[i].cidr; i++) {
		/* Add in increasing prefix order, so larger cidr first */
		if (nets[i].cidr < cidr)
			swap(nets[i].cidr, cidr);
	}
	if (i < host_mask - 1)
		nets[i].cidr = cidr;
}

static inline void
del_cidr(struct chash_nets *nets, u8 host_mask, u8 cidr)
{
	u8 i;

	pr_debug("del_cidr %u", cidr);
	for (i = 0; i < host_mask - 2 && nets[i].cidr; i++) {
		if (nets[i].cidr == cidr)
			nets[i].cidr = cidr = nets[i+1].cidr;
	}
	nets[host_mask - 2].cidr = 0;
}

static void
chash_destroy(struct slist *t, u8 htable_bits, u8 flags)
{
	struct slist *n, *tmp;
	u32 i;
	
	for (i = 0; i < jhash_size(htable_bits); i++)
		slist_for_each_safe(n, tmp, &t[i])
			/* FIXME: slab cache */
			kfree(n);

	ip_set_free(t, flags);
}

static size_t
chash_memsize(const struct chash *h, size_t dsize, u8 host_mask)
{
	struct slist *n;
	u32 i;
	size_t memsize = sizeof(*h)
#ifdef IP_SET_HASH_WITH_NETS
			 + sizeof(struct chash_nets) * (host_mask - 1)
#endif
			 + jhash_size(h->htable_bits) * sizeof(struct slist);
	
	for (i = 0; i < jhash_size(h->htable_bits); i++)
		slist_for_each(n, &h->htable[i])
			memsize += sizeof(struct slist)
				+ h->array_size * dsize;
	
	return memsize;
}

static void
ip_set_hash_flush(struct ip_set *set)
{
	struct chash *h = set->data;
	struct slist *n, *tmp;
	u32 i;
	
	for (i = 0; i < jhash_size(h->htable_bits); i++) {
		slist_for_each_safe(n, tmp, &h->htable[i])
			/* FIXME: slab cache */
			kfree(n);
		h->htable[i].next = NULL;
	}
#ifdef IP_SET_HASH_WITH_NETS
	memset(h->nets, 0, sizeof(struct chash_nets)
			   * (set->family == AF_INET ? 31 : 127));
#endif
	h->elements = 0;
}

static void
ip_set_hash_destroy(struct ip_set *set)
{
	struct chash *h = set->data;

	if (with_timeout(h->timeout))
		del_timer_sync(&h->gc);

	chash_destroy(h->htable, h->htable_bits, set->flags);
	kfree(h);
	
	set->data = NULL;
}

#define JHASH2(data, initval, htable_bits)				\
jhash2((u32 *)(data), sizeof(struct type_pf_elem)/sizeof(u32), initval)	\
	& jhash_mask(htable_bits)

#endif /* _IP_SET_CHASH_H */

/* Type/family dependent function prototypes */

#define type_pf_data_equal	TOKEN(TYPE, PF, _data_equal)
#define type_pf_data_isnull	TOKEN(TYPE, PF, _data_isnull)
#define type_pf_data_copy	TOKEN(TYPE, PF, _data_copy)
#define type_pf_data_swap	TOKEN(TYPE, PF, _data_swap)
#define type_pf_data_zero_out	TOKEN(TYPE, PF, _data_zero_out)
#define type_pf_data_netmask	TOKEN(TYPE, PF, _data_netmask)
#define type_pf_data_list	TOKEN(TYPE, PF, _data_list)
#define type_pf_data_tlist	TOKEN(TYPE, PF, _data_tlist)

#define type_pf_elem		TOKEN(TYPE, PF, _elem)
#define type_pf_telem		TOKEN(TYPE, PF, _telem)
#define type_pf_data_timeout	TOKEN(TYPE, PF, _data_timeout)
#define type_pf_data_expired	TOKEN(TYPE, PF, _data_expired)
#define type_pf_data_swap_timeout TOKEN(TYPE, PF, _data_swap_timeout)
#define type_pf_data_timeout_set TOKEN(TYPE, PF, _data_timeout_set)

#define type_pf_chash_readd	TOKEN(TYPE, PF, _chash_readd)
#define type_pf_chash_del_elem	TOKEN(TYPE, PF, _chash_del_elem)
#define type_pf_chash_add	TOKEN(TYPE, PF, _chash_add)
#define type_pf_chash_del	TOKEN(TYPE, PF, _chash_del)
#define type_pf_chash_test_cidrs TOKEN(TYPE, PF, _chash_test_cidrs)
#define type_pf_chash_test	TOKEN(TYPE, PF, _chash_test)

#define type_pf_chash_treadd	TOKEN(TYPE, PF, _chash_treadd)
#define type_pf_chash_del_telem	TOKEN(TYPE, PF, _chash_del_telem)
#define type_pf_chash_expire	TOKEN(TYPE, PF, _chash_expire)
#define type_pf_chash_tadd	TOKEN(TYPE, PF, _chash_tadd)
#define type_pf_chash_tdel	TOKEN(TYPE, PF, _chash_tdel)
#define type_pf_chash_ttest_cidrs TOKEN(TYPE, PF, _chash_ttest_cidrs)
#define type_pf_chash_ttest	TOKEN(TYPE, PF, _chash_ttest)

#define type_pf_resize		TOKEN(TYPE, PF, _resize)
#define type_pf_tresize		TOKEN(TYPE, PF, _tresize)
#define type_pf_flush		ip_set_hash_flush
#define type_pf_destroy		ip_set_hash_destroy
#define type_pf_head		TOKEN(TYPE, PF, _head)
#define type_pf_list		TOKEN(TYPE, PF, _list)
#define type_pf_tlist		TOKEN(TYPE, PF, _tlist)
#define type_pf_same_set	TOKEN(TYPE, PF, _same_set)
#define type_pf_kadt		TOKEN(TYPE, PF, _kadt)
#define type_pf_uadt		TOKEN(TYPE, PF, _uadt)
#define type_pf_gc		TOKEN(TYPE, PF, _gc)
#define type_pf_gc_init		TOKEN(TYPE, PF, _gc_init)
#define type_pf_variant		TOKEN(TYPE, PF, _variant)
#define type_pf_tvariant	TOKEN(TYPE, PF, _tvariant)

/* Flavour without timeout */

#define chash_data(n, i) \
(struct type_pf_elem *)((char *)(n) + sizeof(struct slist) + (i)*sizeof(struct type_pf_elem))

static int
type_pf_chash_readd(struct chash *h, struct slist *t, u8 htable_bits,
		    const struct type_pf_elem *value, gfp_t gfp_flags)
{
	struct slist *n, *prev;
	struct type_pf_elem *data;
	void *tmp;
	int i = 0, j = 0;
	u32 hash = JHASH2(value, h->initval, htable_bits);

	slist_for_each_prev(prev, n, &t[hash]) {
		for (i = 0; i < h->array_size; i++) {
			data = chash_data(n, i);
			if (type_pf_data_isnull(data)) {
				tmp = n;
				goto found;
			}
		}
		j++;
	}
	if (j < h->chain_limit) {
		tmp = kzalloc(h->array_size * sizeof(struct type_pf_elem)
			      + sizeof(struct slist), gfp_flags);
		if (!tmp)
			return -ENOMEM;
		prev->next = (struct slist *) tmp;
		data = chash_data(tmp, 0);
	} else {
		/* Rehashing */
		return -EAGAIN;
	}
found:
	type_pf_data_copy(data, value);
	return 0;
}

static void
type_pf_chash_del_elem(struct chash *h, struct slist *prev,
		       struct slist *n, int i)
{
	struct type_pf_elem *data = chash_data(n, i);
	struct slist *tmp;
	int j;

	if (n->next != NULL) {
		for (prev = n, tmp = n->next;
		     tmp->next != NULL;
		     prev = tmp, tmp = tmp->next)
		     	/* Find last array */;
		j = 0;
	} else {
		/* Already at last array */
		tmp = n;
		j = i;
	}
	/* Find last non-empty element */
	for (; j < h->array_size - 1; j++)
		if (type_pf_data_isnull(chash_data(tmp, j + 1)))
			break;

	if (!(tmp == n && i == j)) {
		type_pf_data_swap(data, chash_data(tmp, j));
	}
#ifdef IP_SET_HASH_WITH_NETS
	if (--h->nets[data->cidr-1].nets == 0)
		del_cidr(h->nets, HOST_MASK, data->cidr);
#endif
	if (j == 0) {
		prev->next = NULL;
		kfree(tmp);
	} else
		type_pf_data_zero_out(chash_data(tmp, j));

	h->elements--;
}

static int
type_pf_resize(struct ip_set *set, gfp_t gfp_flags, bool retried)
{
	struct chash *h = set->data;
	u8 htable_bits = h->htable_bits;
	struct slist *t, *n;
	const struct type_pf_elem *data;
	u32 i, j;
	u8 oflags, flags;
	int ret;

retry:
	ret = 0;
	htable_bits++;
	if (!htable_bits)
		/* In case we have plenty of memory :-) */
		return -IPSET_ERR_HASH_FULL;
	t = ip_set_alloc(jhash_size(htable_bits) * sizeof(struct slist),
			 gfp_flags, &flags);
	if (!t)
		return -ENOMEM;

	write_lock_bh(&set->lock);
	flags = oflags = set->flags;
	for (i = 0; i < jhash_size(h->htable_bits); i++) {
next_slot:
		slist_for_each(n, &h->htable[i]) {
			for (j = 0; j < h->array_size; j++) {
				data = chash_data(n, j);
				if (type_pf_data_isnull(data)) {
					i++;
					goto next_slot;
				}
				ret = type_pf_chash_readd(h, t, htable_bits,
							  data, gfp_flags);
				if (ret < 0) {
					write_unlock_bh(&set->lock);
					chash_destroy(t, htable_bits, flags);
					if (ret == -EAGAIN)
						goto retry;
					return ret;
				}
			}
		}
	}

	n = h->htable;
	i = h->htable_bits;
	
	h->htable = t;
	h->htable_bits = htable_bits;
	set->flags = flags;
	write_unlock_bh(&set->lock);

	chash_destroy(n, i, oflags);
	
	return 0;
}

static int
type_pf_chash_add(struct ip_set *set, void *value,
		  gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	const struct type_pf_elem *d = value;
	struct slist *n, *prev, *t = h->htable;
	struct type_pf_elem *data;
	void *tmp;
	int i = 0, j = 0;
	u32 hash;

#ifdef IP_SET_HASH_WITH_NETS
	if (h->elements >= h->maxelem || h->nets[d->cidr-1].nets == UINT_MAX)
#else
	if (h->elements >= h->maxelem)
#endif
		return -IPSET_ERR_HASH_FULL;

	hash = JHASH2(value, h->initval, h->htable_bits);
	slist_for_each_prev(prev, n, &t[hash]) {
		for (i = 0; i < h->array_size; i++) {
			data = chash_data(n, i);
			if (type_pf_data_isnull(data)) {
				tmp = n;
				goto found;
			}
			if (type_pf_data_equal(data, d))
				return -IPSET_ERR_EXIST;
		}
		j++;
	}
	if (j < h->chain_limit) {
		tmp = kzalloc(h->array_size * sizeof(struct type_pf_elem)
			      + sizeof(struct slist), gfp_flags);
		if (!tmp)
			return -ENOMEM;
		prev->next = (struct slist *) tmp;
		data = chash_data(tmp, 0);
	} else {
		/* Rehashing */
		return -EAGAIN;
	}
found:
	type_pf_data_copy(data, d);
#ifdef IP_SET_HASH_WITH_NETS
	if (h->nets[d->cidr-1].nets++ == 0)
		add_cidr(h->nets, HOST_MASK, d->cidr);
#endif
	h->elements++;
	return 0;
}

static int
type_pf_chash_del(struct ip_set *set, void *value,
		  gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	const struct type_pf_elem *d = value;
	struct slist *n, *prev;
	int i;
	struct type_pf_elem *data;
	u32 hash = JHASH2(value, h->initval, h->htable_bits);

	slist_for_each_prev(prev, n, &h->htable[hash])
		for (i = 0; i < h->array_size; i++) {
			data = chash_data(n, i);
			if (type_pf_data_isnull(data))
				return -IPSET_ERR_EXIST;
			if (type_pf_data_equal(data, d)) {
				type_pf_chash_del_elem(h, prev, n, i);
				return 0;
			}
		}

	return -IPSET_ERR_EXIST;
}

#ifdef IP_SET_HASH_WITH_NETS
static inline int
type_pf_chash_test_cidrs(struct ip_set *set,
			 struct type_pf_elem *d,
			 gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	struct slist *n;
	const struct type_pf_elem *data;
	int i, j = 0;
	u32 hash;
	u8 host_mask = set->family == AF_INET ? 32 : 128;

retry:
	pr_debug("test by nets");
	for (; j < host_mask - 1 && h->nets[j].cidr; j++) {
		type_pf_data_netmask(d, h->nets[j].cidr);
		hash = JHASH2(d, h->initval, h->htable_bits);
		slist_for_each(n, &h->htable[hash])
			for (i = 0; i < h->array_size; i++) {
				data = chash_data(n, i);
				if (type_pf_data_isnull(data)) {
					j++;
					goto retry;
				}
				if (type_pf_data_equal(data, d))
					return 1;
			}
	}
	return 0;
}
#endif

static inline int
type_pf_chash_test(struct ip_set *set, void *value,
		   gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	struct type_pf_elem *d = value;
	struct slist *n;
	const struct type_pf_elem *data;
	int i;
	u32 hash;
#ifdef IP_SET_HASH_WITH_NETS
	u8 host_mask = set->family == AF_INET ? 32 : 128;

	if (d->cidr == host_mask)
		return type_pf_chash_test_cidrs(set, d, gfp_flags, timeout);
#endif

	hash = JHASH2(d, h->initval, h->htable_bits);
	slist_for_each(n, &h->htable[hash])
		for (i = 0; i < h->array_size; i++) {
			data = chash_data(n, i);
			if (type_pf_data_isnull(data))
				return 0;
			if (type_pf_data_equal(data, d))
				return 1;
		}
	return 0;
}

static int
type_pf_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct chash *h = set->data;
	struct nlattr *nested;
	size_t memsize;
	
	read_lock_bh(&set->lock);
	memsize = chash_memsize(h, with_timeout(h->timeout)
					? sizeof(struct type_pf_telem)
					: sizeof(struct type_pf_elem),
				set->family == AF_INET ? 32 : 128);
	read_unlock_bh(&set->lock);

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT_NET32(skb, IPSET_ATTR_HASHSIZE,
		      htonl(jhash_size(h->htable_bits)));
	NLA_PUT_NET32(skb, IPSET_ATTR_MAXELEM, htonl(h->maxelem));
#ifdef IP_SET_HASH_WITH_NETMASK
	if (h->netmask != HOST_MASK)
		NLA_PUT_U8(skb, IPSET_ATTR_NETMASK, h->netmask);
#endif
	NLA_PUT_NET32(skb, IPSET_ATTR_REFERENCES,
		      htonl(atomic_read(&set->ref) - 1));
	NLA_PUT_NET32(skb, IPSET_ATTR_MEMSIZE, htonl(memsize));
	if (with_timeout(h->timeout))
		NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT, htonl(h->timeout));
	ipset_nest_end(skb, nested);
	
	return 0;
nla_put_failure:
	return -EFAULT;
}

static int
type_pf_list(struct ip_set *set,
	     struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct chash *h = set->data;
	struct nlattr *atd, *nested;
	struct slist *n;
	const struct type_pf_elem *data;
	u32 first = cb->args[2];
	int i;

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EFAULT;
	pr_debug("list hash set %s", set->name);
	for (; cb->args[2] < jhash_size(h->htable_bits); cb->args[2]++) {
		slist_for_each(n, &h->htable[cb->args[2]]) {
			for (i = 0; i < h->array_size; i++) {
				data = chash_data(n, i);
				if (type_pf_data_isnull(data))
					break;
				pr_debug("list hash %lu slist %p i %u",
					 cb->args[2], n, i);
				nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
				if (!nested) {
					if (cb->args[2] == first) {
						nla_nest_cancel(skb, atd);
						return -EFAULT;
					} else
						goto nla_put_failure;
				}
				if (type_pf_data_list(skb, data))
					goto nla_put_failure;
				ipset_nest_end(skb, nested);
			}
		}
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
type_pf_kadt(struct ip_set *set, const struct sk_buff * skb,
	     enum ipset_adt adt, u8 pf, u8 dim, u8 flags);
static int
type_pf_uadt(struct ip_set *set, struct nlattr *head, int len,
	     enum ipset_adt adt, u32 *lineno, u32 flags);

static const struct ip_set_type_variant type_pf_variant __read_mostly = {
	.kadt	= type_pf_kadt,
	.uadt	= type_pf_uadt,
	.adt	= {
		[IPSET_ADD] = type_pf_chash_add,
		[IPSET_DEL] = type_pf_chash_del,
		[IPSET_TEST] = type_pf_chash_test,
	},
	.destroy = type_pf_destroy,
	.flush	= type_pf_flush,
	.head	= type_pf_head,
	.list	= type_pf_list,
	.resize	= type_pf_resize,
	.same_set = type_pf_same_set,
};

/* Flavour with timeout support */

#define chash_tdata(n, i) \
(struct type_pf_elem *)((char *)(n) + sizeof(struct slist) + (i)*sizeof(struct type_pf_telem))

static inline u32
type_pf_data_timeout(const struct type_pf_elem *data)
{
	const struct type_pf_telem *tdata =
		(const struct type_pf_telem *) data;

	return tdata->timeout;
}

static inline bool
type_pf_data_expired(const struct type_pf_elem *data)
{
	const struct type_pf_telem *tdata =
		(const struct type_pf_telem *) data;

	return ip_set_timeout_expired(tdata->timeout);
}

static inline void
type_pf_data_swap_timeout(struct type_pf_elem *src,
			  struct type_pf_elem *dst)
{
	struct type_pf_telem *x = (struct type_pf_telem *) src;
	struct type_pf_telem *y = (struct type_pf_telem *) dst;

	swap(x->timeout, y->timeout);
}

static inline void
type_pf_data_timeout_set(struct type_pf_elem *data, u32 timeout)
{
	struct type_pf_telem *tdata = (struct type_pf_telem *) data;

	tdata->timeout = ip_set_timeout_set(timeout);
}

static int
type_pf_chash_treadd(struct chash *h, struct slist *t, u8 htable_bits,
		     const struct type_pf_elem *value,
		     gfp_t gfp_flags, u32 timeout)
{
	struct slist *n, *prev;
	struct type_pf_elem *data;
	void *tmp;
	int i = 0, j = 0;
	u32 hash = JHASH2(value, h->initval, htable_bits);

	slist_for_each_prev(prev, n, &t[hash]) {
		for (i = 0; i < h->array_size; i++) {
			data = chash_tdata(n, i);
			if (type_pf_data_isnull(data)) {
			    	tmp = n;
			    	goto found;
			}
		}
		j++;
	}
	if (j < h->chain_limit) {
		tmp = kzalloc(h->array_size * sizeof(struct type_pf_telem)
			      + sizeof(struct slist), gfp_flags);
		if (!tmp)
			return -ENOMEM;
		prev->next = (struct slist *) tmp;
		data = chash_tdata(tmp, 0);
	} else {
		/* Rehashing */
		return -EAGAIN;
	}
found:
	type_pf_data_copy(data, value);
	type_pf_data_timeout_set(data, timeout);
	return 0;
}

static void
type_pf_chash_del_telem(struct chash *h, struct slist *prev,
		        struct slist *n, int i)
{
	struct type_pf_elem *d, *data = chash_tdata(n, i);
	struct slist *tmp;
	int j;

	pr_debug("del %u", i);
	if (n->next != NULL) {
		for (prev = n, tmp = n->next;
		     tmp->next != NULL;
		     prev = tmp, tmp = tmp->next)
		     	/* Find last array */;
		j = 0;
	} else {
		/* Already at last array */
		tmp = n;
		j = i;
	}
	/* Find last non-empty element */
	for (; j < h->array_size - 1; j++)
		if (type_pf_data_isnull(chash_tdata(tmp, j + 1)))
			break;

	d = chash_tdata(tmp, j);
	if (!(tmp == n && i == j)) {
		type_pf_data_swap(data, d);
		type_pf_data_swap_timeout(data, d);
	}
#ifdef IP_SET_HASH_WITH_NETS
	if (--h->nets[data->cidr-1].nets == 0)
		del_cidr(h->nets, HOST_MASK, data->cidr);
#endif
	if (j == 0) {
		prev->next = NULL;
		kfree(tmp);
	} else
		type_pf_data_zero_out(d);

	h->elements--;
}

static void
type_pf_chash_expire(struct chash *h)
{
	struct slist *n, *prev;
	struct type_pf_elem *data;
	u32 i;
	int j;
	
	for (i = 0; i < jhash_size(h->htable_bits); i++)
		slist_for_each_prev(prev, n, &h->htable[i])
			for (j = 0; j < h->array_size; j++) {
				data = chash_tdata(n, j);
				if (type_pf_data_isnull(data))
					break;
				if (type_pf_data_expired(data)) {
					pr_debug("expire %u/%u", i, j);
					type_pf_chash_del_telem(h, prev, n, j);
				}
			}
}

static int
type_pf_tresize(struct ip_set *set, gfp_t gfp_flags, bool retried)
{
	struct chash *h = set->data;
	u8 htable_bits = h->htable_bits;
	struct slist *t, *n;
	const struct type_pf_elem *data;
	u32 i, j;
	u8 oflags, flags;
	int ret;

	/* Try to cleanup once */
	if (!retried) {
		i = h->elements;
		write_lock_bh(&set->lock);
		type_pf_chash_expire(set->data);
		write_unlock_bh(&set->lock);
		if (h->elements <  i)
			return 0;
	}

retry:
	ret = 0;
	htable_bits++;
	if (!htable_bits)
		/* In case we have plenty of memory :-) */
		return -IPSET_ERR_HASH_FULL;
	t = ip_set_alloc(jhash_size(htable_bits) * sizeof(struct slist),
			 gfp_flags, &flags);
	if (!t)
		return -ENOMEM;

	write_lock_bh(&set->lock);
	flags = oflags = set->flags;
	for (i = 0; i < jhash_size(h->htable_bits); i++) {
next_slot:
		slist_for_each(n, &h->htable[i]) {
			for (j = 0; j < h->array_size; j++) {
				data = chash_tdata(n, j);
				if (type_pf_data_isnull(data)) {
					i++;
					goto next_slot;
				}
				ret = type_pf_chash_treadd(h, t, htable_bits,
							   data, gfp_flags,
							   type_pf_data_timeout(data));
				if (ret < 0) {
					write_unlock_bh(&set->lock);
					chash_destroy(t, htable_bits, flags);
					if (ret == -EAGAIN)
						goto retry;
					return ret;
				}
			}
		}
	}

	n = h->htable;
	i = h->htable_bits;
	
	h->htable = t;
	h->htable_bits = htable_bits;
	set->flags = flags;
	write_unlock_bh(&set->lock);

	chash_destroy(n, i, oflags);
	
	return 0;
}

static int
type_pf_chash_tadd(struct ip_set *set, void *value,
		   gfp_t gfp_flags, u32 timeout)
{	
	struct chash *h = set->data;
	const struct type_pf_elem *d = value;
	struct slist *n, *prev, *t = h->htable;
	struct type_pf_elem *data;
	void *tmp;
	int i = 0, j = 0;
	u32 hash;

	if (h->elements >= h->maxelem)
		/* FIXME: when set is full, we slow down here */
		type_pf_chash_expire(h);
#ifdef IP_SET_HASH_WITH_NETS
	if (h->elements >= h->maxelem || h->nets[d->cidr-1].nets == UINT_MAX)
#else
	if (h->elements >= h->maxelem)
#endif
		return -IPSET_ERR_HASH_FULL;

	hash = JHASH2(d, h->initval, h->htable_bits);
	slist_for_each_prev(prev, n, &t[hash]) {
		for (i = 0; i < h->array_size; i++) {
			data = chash_tdata(n, i);
			if (type_pf_data_isnull(data)
			    || type_pf_data_expired(data)) {
			    	tmp = n;
			    	goto found;
			}
			if (type_pf_data_equal(data, d))
				return -IPSET_ERR_EXIST;
		}
		j++;
	}
	if (j < h->chain_limit) {
		tmp = kzalloc(h->array_size * sizeof(struct type_pf_telem)
			      + sizeof(struct slist), gfp_flags);
		if (!tmp)
			return -ENOMEM;
		prev->next = (struct slist *) tmp;
		data = chash_tdata(tmp, 0);
	} else {
		/* Rehashing */
		return -EAGAIN;
	}
found:
	if (type_pf_data_isnull(data)) {
	      	h->elements++;
#ifdef IP_SET_HASH_WITH_NETS
	} else {
		if (--h->nets[data->cidr-1].nets == 0)
			del_cidr(h->nets, HOST_MASK, data->cidr);
	}
     	if (h->nets[d->cidr-1].nets++ == 0) {
      		add_cidr(h->nets, HOST_MASK, d->cidr);
#endif
	}
	type_pf_data_copy(data, d);
	type_pf_data_timeout_set(data, timeout);
	return 0;
}

static int
type_pf_chash_tdel(struct ip_set *set, void *value,
		   gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	const struct type_pf_elem *d = value;
	struct slist *n, *prev;
	int i, ret = 0;
	struct type_pf_elem *data;
	u32 hash = JHASH2(value, h->initval, h->htable_bits);

	slist_for_each_prev(prev, n, &h->htable[hash])
		for (i = 0; i < h->array_size; i++) {
			data = chash_tdata(n, i);
			if (type_pf_data_isnull(data))
				return -IPSET_ERR_EXIST;
			if (type_pf_data_equal(data, d)) {
				if (type_pf_data_expired(data))
				    	ret = -IPSET_ERR_EXIST;
				type_pf_chash_del_telem(h, prev, n, i);
				return ret;
			}
		}

	return -IPSET_ERR_EXIST;
}

#ifdef IP_SET_HASH_WITH_NETS
static inline int
type_pf_chash_ttest_cidrs(struct ip_set *set,
			  struct type_pf_elem *d,
			  gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	struct type_pf_elem *data;
	struct slist *n;
	int i, j = 0;
	u32 hash;
	u8 host_mask = set->family == AF_INET ? 32 : 128;

retry:
	for (; j < host_mask - 1 && h->nets[j].cidr; j++) {
		type_pf_data_netmask(d, h->nets[j].cidr);
		hash = JHASH2(d, h->initval, h->htable_bits);
		slist_for_each(n, &h->htable[hash])
			for (i = 0; i < h->array_size; i++) {
				data = chash_tdata(n, i);
				if (type_pf_data_isnull(data)) {
					j++;
					goto retry;
				}
				if (type_pf_data_equal(data, d))
					return !type_pf_data_expired(data);
			}
	}
	return 0;
}
#endif

static inline int
type_pf_chash_ttest(struct ip_set *set, void *value,
		    gfp_t gfp_flags, u32 timeout)
{
	struct chash *h = set->data;
	struct type_pf_elem *data, *d = value;
	struct slist *n;
	int i;
	u32 hash;
#ifdef IP_SET_HASH_WITH_NETS
	u8 host_mask = set->family == AF_INET ? 32 : 128;

	if (d->cidr == host_mask)
		return type_pf_chash_ttest_cidrs(set, d, gfp_flags,
						 timeout);
#endif
	hash = JHASH2(d, h->initval, h->htable_bits);
	slist_for_each(n, &h->htable[hash])
		for (i = 0; i < h->array_size; i++) {
			data = chash_tdata(n, i);
			if (type_pf_data_isnull(data))
				return 0;
			if (type_pf_data_equal(data, d))
				return !type_pf_data_expired(data);
		}
	return 0;
}

static int
type_pf_tlist(struct ip_set *set,
	      struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct chash *h = set->data;
	struct nlattr *atd, *nested;
	struct slist *n;
	const struct type_pf_elem *data;
	u32 first = cb->args[2];
	int i;

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EFAULT;
	for (; cb->args[2] < jhash_size(h->htable_bits); cb->args[2]++) {
		slist_for_each(n, &h->htable[cb->args[2]]) {
			for (i = 0; i < h->array_size; i++) {
				data = chash_tdata(n, i);
				pr_debug("list %p %u", n, i);
				if (type_pf_data_isnull(data))
					break;
				if (type_pf_data_expired(data))
					continue;
				pr_debug("do list %p %u", n, i);
				nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
				if (!nested) {
					if (cb->args[2] == first) {
						nla_nest_cancel(skb, atd);
						return -EFAULT;
					} else
						goto nla_put_failure;
				}
				if (type_pf_data_tlist(skb, data))
					goto nla_put_failure;
				ipset_nest_end(skb, nested);
			}
		}
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

static const struct ip_set_type_variant type_pf_tvariant __read_mostly = {
	.kadt	= type_pf_kadt,
	.uadt	= type_pf_uadt,
	.adt	= {
		[IPSET_ADD] = type_pf_chash_tadd,
		[IPSET_DEL] = type_pf_chash_tdel,
		[IPSET_TEST] = type_pf_chash_ttest,
	},
	.destroy = type_pf_destroy,
	.flush	= type_pf_flush,
	.head	= type_pf_head,
	.list	= type_pf_tlist,
	.resize	= type_pf_tresize,
	.same_set = type_pf_same_set,
};

static void
type_pf_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct chash *h = set->data;

	pr_debug("called");
	write_lock_bh(&set->lock);
	type_pf_chash_expire(h);
	write_unlock_bh(&set->lock);

	h->gc.expires = jiffies + IPSET_GC_PERIOD(h->timeout) * HZ;
	add_timer(&h->gc);
}

static inline void
type_pf_gc_init(struct ip_set *set)
{
	struct chash *h = set->data;
	
	init_timer(&h->gc);
	h->gc.data = (unsigned long) set;
	h->gc.function = type_pf_gc;
	h->gc.expires = jiffies + IPSET_GC_PERIOD(h->timeout) * HZ;
	add_timer(&h->gc);
	pr_debug("gc initialized, run in every %u", IPSET_GC_PERIOD(h->timeout));
}

#undef type_pf_data_equal
#undef type_pf_data_isnull
#undef type_pf_data_copy
#undef type_pf_data_swap
#undef type_pf_data_zero_out
#undef type_pf_data_list
#undef type_pf_data_tlist

#undef type_pf_elem
#undef type_pf_telem
#undef type_pf_data_timeout
#undef type_pf_data_expired
#undef type_pf_data_swap_timeout
#undef type_pf_data_netmask
#undef type_pf_data_timeout_set

#undef type_pf_chash_readd
#undef type_pf_chash_del_elem
#undef type_pf_chash_add
#undef type_pf_chash_del
#undef type_pf_chash_test_cidrs
#undef type_pf_chash_test

#undef type_pf_chash_treadd
#undef type_pf_chash_del_telem
#undef type_pf_chash_expire
#undef type_pf_chash_tadd
#undef type_pf_chash_tdel
#undef type_pf_chash_ttest_cidrs
#undef type_pf_chash_ttest

#undef type_pf_resize
#undef type_pf_tresize
#undef type_pf_flush
#undef type_pf_destroy
#undef type_pf_head
#undef type_pf_list
#undef type_pf_tlist
#undef type_pf_same_set
#undef type_pf_kadt
#undef type_pf_uadt
#undef type_pf_gc
#undef type_pf_gc_init
#undef type_pf_variant
#undef type_pf_tvariant

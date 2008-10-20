/* Copyright (C) 2008 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the setlist type */

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>

#include <linux/netfilter_ipv4/ip_set.h>
#include <linux/netfilter_ipv4/ip_set_bitmaps.h>
#include <linux/netfilter_ipv4/ip_set_setlist.h>

/*
 * before ==> id, ref
 * after  ==> ref, id
 */

static inline bool
next_id_eq(const struct ip_set_setlist *map, int i, ip_set_id_t id)
{
	return i < map->size && map->id[i] == id;
}

static int
setlist_utest(struct ip_set *set, const void *data, size_t size,
	       ip_set_ip_t *hash_ip)
{
	const struct ip_set_setlist *map = set->data;
	const struct ip_set_req_setlist *req = data;
	ip_set_id_t id, ref = IP_SET_INVALID_ID;
	int i, res = 0;
	struct ip_set *s;
	
	if (req->before && req->ref[0] == '\0')
		return -EINVAL;

	id = __ip_set_get_byname(req->name, &s);
	if (id == IP_SET_INVALID_ID)
		return -EEXIST;
	if (req->ref[0] != '\0') {
		ref = __ip_set_get_byname(req->ref, &s);
		if (ref == IP_SET_INVALID_ID) {
			res = -EEXIST;
			goto finish;
		}
	}
	for (i = 0; i < map->size
		    && map->id[i] != IP_SET_INVALID_ID; i++) {
		if (req->before && map->id[i] == id) {
		    	res = next_id_eq(map, i + 1, ref);
		    	break;
		} else if (!req->before) {
			if ((ref == IP_SET_INVALID_ID
			     && map->id[i] == id)
			    || (map->id[i] == ref
			        && next_id_eq(map, i + 1, id))) {
			        res = 1;
			        break;
			}
		}
	}
	if (ref != IP_SET_INVALID_ID)
		__ip_set_put_byid(ref);
finish:
	__ip_set_put_byid(id);
	return res;
}

static int
setlist_ktest(struct ip_set *set,
	       const struct sk_buff *skb,
	       ip_set_ip_t *hash_ip,
	       const u_int32_t *flags,
	       unsigned char index)
{
	struct ip_set_setlist *map = set->data;
	int i, res = 0;
	
	for (i = 0; i < map->size
		    && map->id[i] != IP_SET_INVALID_ID
		    && res == 0; i++)
		res = ip_set_testip_kernel(map->id[i], skb, flags);
	return res;
}

static inline int
insert_setlist(struct ip_set_setlist *map, int i, ip_set_id_t id)
{
	ip_set_id_t tmp;
	int j;

	printk("i: %u, last %u\n", i, map->id[map->size - 1]);	
	if (i >= map->size || map->id[map->size - 1] != IP_SET_INVALID_ID)
		return -ERANGE;
	
	for (j = i; j < map->size
		    && id != IP_SET_INVALID_ID; j++) {
		tmp = map->id[j];
		map->id[j] = id;
		id = tmp;
	}
	return 0;
}

static int
setlist_uadd(struct ip_set *set, const void *data, size_t size,
	     ip_set_ip_t *hash_ip)
{
	struct ip_set_setlist *map = set->data;
	const struct ip_set_req_setlist *req = data;
	ip_set_id_t id, ref = IP_SET_INVALID_ID;
	int i, res = -ERANGE;
	struct ip_set *s;
	
	if (req->before && req->ref[0] == '\0')
		return -EINVAL;

	id = __ip_set_get_byname(req->name, &s);
	if (id == IP_SET_INVALID_ID)
		return -EEXIST;
	/* "Loop detection" */
	if (strcmp(s->type->typename, "setlist") == 0)
		goto finish;

	if (req->ref[0] != '\0') {
		ref = __ip_set_get_byname(req->ref, &s);
		if (ref == IP_SET_INVALID_ID) {
			res = -EEXIST;
			goto finish;
		}
	}
	for (i = 0; i < map->size; i++) {
		if (map->id[i] != ref)
			continue;
		if (req->before) 
			res = insert_setlist(map, i, id);
		else
			res = insert_setlist(map,
				ref == IP_SET_INVALID_ID ? i : i + 1,
				id);
		break;
	}
	if (ref != IP_SET_INVALID_ID)
		__ip_set_put_byid(ref);
	/* In case of success, we keep the reference to the id */
finish:
	if (res != 0)
		__ip_set_put_byid(id);
	return res;
}

static int
setlist_kadd(struct ip_set *set,
	     const struct sk_buff *skb,
	     ip_set_ip_t *hash_ip,
	     const u_int32_t *flags,
	     unsigned char index)
{
	struct ip_set_setlist *map = set->data;
	int i, res = -EINVAL;
	
	for (i = 0; i < map->size
		    && map->id[i] != IP_SET_INVALID_ID
		    && res != 0; i++)
		res = ip_set_addip_kernel(map->id[i], skb, flags);
	return res;
}

static inline bool
unshift_setlist(struct ip_set_setlist *map, int i)
{
	int j;
	
	for (j = i; j < map->size - 1; j++)
		map->id[j] = map->id[j+1];
	map->id[map->size-1] = IP_SET_INVALID_ID;
	return 0;
}

static int
setlist_udel(struct ip_set *set, const void *data, size_t size,
	     ip_set_ip_t *hash_ip)
{
	struct ip_set_setlist *map = set->data;
	const struct ip_set_req_setlist *req = data;
	ip_set_id_t id, ref = IP_SET_INVALID_ID;
	int i, res = -EEXIST;
	struct ip_set *s;
	
	if (req->before && req->ref[0] == '\0')
		return -EINVAL;

	id = __ip_set_get_byname(req->name, &s);
	if (id == IP_SET_INVALID_ID)
		return -EEXIST;
	if (req->ref[0] != '\0') {
		ref = __ip_set_get_byname(req->ref, &s);
		if (ref == IP_SET_INVALID_ID)
			goto finish;
	}
	for (i = 0; i < map->size
	            && map->id[i] != IP_SET_INVALID_ID; i++) {
		if (req->before) {
			if (map->id[i] == id
			    && next_id_eq(map, i + 1, ref)) {
				res = unshift_setlist(map, i);
				break;
			}
		} else if (ref == IP_SET_INVALID_ID) {
			if (map->id[i] == id) {
				res = unshift_setlist(map, i);
				break;
			}
		} else if (map->id[i] == ref
			   && next_id_eq(map, i + 1, id)) {
			res = unshift_setlist(map, i + 1);
			break;
		}
	}
	if (ref != IP_SET_INVALID_ID)
		__ip_set_put_byid(ref);
finish:
	__ip_set_put_byid(id);
	/* In case of success, release the reference to the id */
	if (res == 0)
		__ip_set_put_byid(id);
	return res;
}

static int
setlist_kdel(struct ip_set *set,
	     const struct sk_buff *skb,
	     ip_set_ip_t *hash_ip,
	     const u_int32_t *flags,
	     unsigned char index)
{
	struct ip_set_setlist *map = set->data;
	int i, res = -EINVAL;
	
	for (i = 0; i < map->size
		    && map->id[i] != IP_SET_INVALID_ID
		    && res != 0; i++)
		res = ip_set_delip_kernel(map->id[i], skb, flags);
	return res;
}

static int
setlist_create(struct ip_set *set, const void *data, size_t size)
{
	struct ip_set_setlist *map;
	const struct ip_set_req_setlist_create *req = data;
	int i;
	
	map = kmalloc(sizeof(struct ip_set_setlist) +
		      req->size * sizeof(ip_set_id_t), GFP_KERNEL);
	if (!map)
		return -ENOMEM;
	map->size = req->size;
	for (i = 0; i < map->size; i++)
		map->id[i] = IP_SET_INVALID_ID;
	
	set->data = map;
	return 0;
}                        

static void
setlist_destroy(struct ip_set *set)
{
	struct ip_set_setlist *map = set->data;
	int i;
	
	for (i = 0; i < map->size
		    && map->id[i] != IP_SET_INVALID_ID; i++)
		__ip_set_put_byid(map->id[i]);

	kfree(map);
	set->data = NULL;
}

static void
setlist_flush(struct ip_set *set)
{
	struct ip_set_setlist *map = set->data;
	int i;
	
	for (i = 0; i < map->size
		    && map->id[i] != IP_SET_INVALID_ID; i++) {
		__ip_set_put_byid(map->id[i]);
		map->id[i] = IP_SET_INVALID_ID;
	}
}

static void
setlist_list_header(const struct ip_set *set, void *data)
{
	const struct ip_set_setlist *map = set->data;
	struct ip_set_req_setlist_create *header = data;
	
	header->size = map->size;
}

static int
setlist_list_members_size(const struct ip_set *set)
{
	const struct ip_set_setlist *map = set->data;
	
	return map->size * sizeof(ip_set_id_t);
}

static void
setlist_list_members(const struct ip_set *set, void *data)
{
	struct ip_set_setlist *map = set->data;
	int i;
	
	for (i = 0; i < map->size; i++)
		*((ip_set_id_t *)data + i) = map->id[i];
}

IP_SET_TYPE(setlist, IPSET_TYPE_SETNAME | IPSET_DATA_SINGLE)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("setlist type of IP sets");

REGISTER_MODULE(setlist)

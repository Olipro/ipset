#ifndef _LIBIPT_SET_H
#define _LIBIPT_SET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

static int get_set_getsockopt(void *data, size_t * size)
{
	int sockfd = -1;
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
		exit_error(OTHER_PROBLEM,
			   "Can't open socket to ipset.\n");
	/* Send! */
	return getsockopt(sockfd, SOL_IP, SO_IP_SET, data, size);
}

static void get_set_byname(const char *setname, struct ipt_set_info *info)
{
	struct ip_set_req_get req;
	int size = sizeof(struct ip_set_req_get);
	int res;

	req.op = IP_SET_OP_GETSET_BYNAME;
	strncpy(req.name, setname, IP_SET_MAXNAMELEN);
	req.name[IP_SET_MAXNAMELEN - 1] = '\0';
	res = get_set_getsockopt(&req, &size);
	if (res != 0)
		exit_error(OTHER_PROBLEM,
			   "Problem when communicating with ipset. errno=%d.\n",
			   errno);
	if (size != sizeof(struct ip_set_req_get))
		exit_error(OTHER_PROBLEM,
			   "Incorrect return size from kernel during ipset lookup, "
			   "(want %d, got %d)\n",
			   sizeof(struct ip_set_req_get), size);
	if (req.id < 0)
		exit_error(PARAMETER_PROBLEM,
			   "Set %s doesn't exist.\n", setname);

	info->id = req.id;
}

static void get_set_byid(char * setname, unsigned id)
{
	struct ip_set_req_get req;
	int size = sizeof(struct ip_set_req_get);
	int res;

	req.op = IP_SET_OP_GETSET_BYID;
	req.id = id;
	res = get_set_getsockopt(&req, &size);
	if (res != 0)
		exit_error(OTHER_PROBLEM,
			   "Problem when communicating with ipset. errno=%d.\n",
			   errno);
	if (size != sizeof(struct ip_set_req_get))
		exit_error(OTHER_PROBLEM,
			   "Incorrect return size from kernel during ipset lookup, "
			   "(want %d, got %d)\n",
			   sizeof(struct ip_set_req_get), size);
	if (req.id < 0)
		exit_error(PARAMETER_PROBLEM,
			   "Set id %i in kernel doesn't exist.\n", id);

	strncpy(setname, req.name, IP_SET_MAXNAMELEN);
}

static void
parse_pool(const char *optarg, struct ipt_set_info *info)
{
	char *saved = strdup(optarg);
	char *ptr, *tmp = saved;

	ptr = strsep(&tmp, ":");
	get_set_byname(ptr, info);
	
	while (info->set_level < IP_SET_SETIP_LEVELS && tmp) {
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->flags[info->set_level++] |= IPSET_SRC;
		else if (strncmp(ptr, "dst", 3) == 0)
			info->flags[info->set_level++] |= IPSET_DST;
		else
			exit_error(PARAMETER_PROBLEM,
				   "You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp || info->set_level >= IP_SET_SETIP_LEVELS)
		exit_error(PARAMETER_PROBLEM,
			   "Defined childset level is deeper that %i.", 
			   IP_SET_SETIP_LEVELS);

	free(saved);
}

static int
parse_ipflags(const char *optarg, struct ipt_set_info *info)
{
	char *saved = strdup(optarg);
	char *ptr, *tmp = saved;
	int overwrite = 0;

	info->ip_level = info->set_level;
	
	while (info->ip_level < IP_SET_LEVELS && tmp) {
		if (*tmp == '+') {
			info->flags[info->ip_level] |= IPSET_ADD_OVERWRITE;
			tmp++;
			overwrite++;
		}
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->flags[info->ip_level++] |= IPSET_SRC;
		else if (strncmp(ptr, "dst", 3) == 0)
			info->flags[info->ip_level++] |= IPSET_DST;
		else
			exit_error(PARAMETER_PROBLEM,
				   "You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp || info->ip_level >= IP_SET_LEVELS)
		exit_error(PARAMETER_PROBLEM,
			   "Defined level is deeper that %i.", 
			   IP_SET_LEVELS);
			   
	free(saved);
	return overwrite;
}

#endif /*_LIBIPT_SET_H*/

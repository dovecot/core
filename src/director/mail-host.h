#ifndef MAIL_HOST_H
#define MAIL_HOST_H

#include "network.h"

struct mail_host_list;

struct mail_host {
	unsigned int user_count;
	unsigned int vhost_count;

	struct ip_addr ip;
};
ARRAY_DEFINE_TYPE(mail_host, struct mail_host *);

struct mail_host *
mail_host_add_ip(struct mail_host_list *list, const struct ip_addr *ip);
struct mail_host *
mail_host_lookup(struct mail_host_list *list, const struct ip_addr *ip);
struct mail_host *
mail_host_get_by_hash(struct mail_host_list *list, unsigned int hash);

int mail_hosts_parse_and_add(struct mail_host_list *list,
			     const char *hosts_string);
void mail_host_set_vhost_count(struct mail_host_list *list,
			       struct mail_host *host,
			       unsigned int vhost_count);
void mail_host_remove(struct mail_host_list *list, struct mail_host *host);

const ARRAY_TYPE(mail_host) *mail_hosts_get(struct mail_host_list *list);

struct mail_host_list *mail_hosts_init(void);
void mail_hosts_deinit(struct mail_host_list **list);

struct mail_host_list *mail_hosts_dup(const struct mail_host_list *src);

#endif

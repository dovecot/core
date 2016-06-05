#ifndef MAIL_HOST_H
#define MAIL_HOST_H

#include "net.h"

struct mail_host_list;

struct mail_host {
	struct mail_host_list *list;

	unsigned int user_count;
	unsigned int vhost_count;
	/* server up/down. down=TRUE has effectively the same result as if
	   vhost_count=0. */
	bool down;
	time_t last_updown_change;

	struct ip_addr ip;
	char *hostname;
	struct mail_tag *tag;

	/* host was recently changed and ring hasn't synced yet since */
	bool desynced:1;
};
ARRAY_DEFINE_TYPE(mail_host, struct mail_host *);

struct mail_host *
mail_host_add_ip(struct mail_host_list *list, const struct ip_addr *ip,
		 const char *tag_name);
struct mail_host *
mail_host_add_hostname(struct mail_host_list *list, const char *hostname,
		       const struct ip_addr *ip, const char *tag_name);
struct mail_host *
mail_host_lookup(struct mail_host_list *list, const struct ip_addr *ip);
struct mail_host *
mail_host_get_by_hash(struct mail_host_list *list, unsigned int hash,
		      const char *tag_name);

int mail_hosts_parse_and_add(struct mail_host_list *list,
			     const char *hosts_string);
const char *mail_host_get_tag(struct mail_host *host);
void mail_host_set_tag(struct mail_host *host, const char *tag_name);
void mail_host_set_down(struct mail_host *host, bool down, time_t timestamp);
void mail_host_set_vhost_count(struct mail_host *host,
			       unsigned int vhost_count);
void mail_host_remove(struct mail_host *host);

void mail_hosts_set_synced(struct mail_host_list *list);
unsigned int mail_hosts_hash(struct mail_host_list *list);
bool mail_hosts_have_usable(struct mail_host_list *list);
const ARRAY_TYPE(mail_host) *mail_hosts_get(struct mail_host_list *list);
bool mail_hosts_have_tags(struct mail_host_list *list);

struct mail_host_list *mail_hosts_init(bool consistent_hashing);
void mail_hosts_deinit(struct mail_host_list **list);

struct mail_host_list *mail_hosts_dup(const struct mail_host_list *src);

#endif

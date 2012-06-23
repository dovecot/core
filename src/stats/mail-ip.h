#ifndef MAIL_IP_H
#define MAIL_IP_H

extern struct mail_ip *stable_mail_ips;

struct mail_ip *mail_ip_login(const struct ip_addr *ip_addr);
struct mail_ip *mail_ip_lookup(const struct ip_addr *ip_addr);
void mail_ip_refresh(struct mail_ip *ip, const struct mail_stats *diff_stats)
	ATTR_NULL(2);

void mail_ip_ref(struct mail_ip *ip);
void mail_ip_unref(struct mail_ip **ip);

void mail_ips_free_memory(void);
void mail_ips_init(void);
void mail_ips_deinit(void);

#endif

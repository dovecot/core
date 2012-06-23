#ifndef MAIL_DOMAIN_H
#define MAIL_DOMAIN_H

struct mail_stats;

extern struct mail_domain *stable_mail_domains;

struct mail_domain *mail_domain_login(const char *name);
struct mail_domain *mail_domain_lookup(const char *name);
void mail_domain_refresh(struct mail_domain *domain,
			 const struct mail_stats *diff_stats) ATTR_NULL(2);

void mail_domain_ref(struct mail_domain *domain);
void mail_domain_unref(struct mail_domain **domain);

void mail_domains_free_memory(void);
void mail_domains_init(void);
void mail_domains_deinit(void);

#endif

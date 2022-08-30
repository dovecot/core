#ifndef DOVEADM_WHO_H
#define DOVEADM_WHO_H

#include "guid.h"

struct who_line {
	const char *username;
	const char *service;
	guid_128_t conn_guid;
	const char *const *alt_usernames;
	struct ip_addr ip;
	struct ip_addr dest_ip;
	pid_t pid;
};


struct who_filter {
	const char *username;

	const char *alt_username_field;
	unsigned int alt_username_idx;

	struct ip_addr dest_ip;

	struct ip_addr net_ip;
	unsigned int net_bits;
};

struct who_context {
	const char *anvil_path;
	struct who_filter filter;

	pool_t pool;
	struct event *event;
	HASH_TABLE(struct who_user *, struct who_user *) users;
};

typedef void who_callback_t(struct who_context *ctx,
			    const struct who_line *line);

int who_parse_args(struct who_context *ctx, const char *alt_username_field,
		   const struct ip_addr *dest_ip, const char *const *masks);

bool who_line_filter_match(const struct who_line *line,
			   const struct who_filter *filter);

struct doveadm_who_iter *doveadm_who_iter_init(const char *anvil_path);
/* Returns TRUE if ok, FALSE if filter can never match anything. */
bool doveadm_who_iter_init_filter(struct doveadm_who_iter *iter,
				  struct who_filter *filter);
bool doveadm_who_iter_next(struct doveadm_who_iter *iter,
			   struct who_line *who_line_r);
int doveadm_who_iter_deinit(struct doveadm_who_iter **_iter,
			    const char **error_r);

#endif /* DOVEADM_WHO_H */

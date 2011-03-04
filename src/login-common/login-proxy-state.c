/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "hash.h"
#include "strescape.h"
#include "fd-set-nonblock.h"
#include "login-proxy-state.h"

#include <unistd.h>
#include <fcntl.h>

struct login_proxy_state {
	struct hash_table *hash;
	pool_t pool;

	const char *notify_path;
	int notify_fd;

	unsigned int notify_fd_broken:1;
};

static unsigned int login_proxy_record_hash(const void *p)
{
	const struct login_proxy_record *rec = p;

	return net_ip_hash(&rec->ip) ^ rec->port;
}

static int login_proxy_record_cmp(const void *p1, const void *p2)
{
	const struct login_proxy_record *rec1 = p1, *rec2 = p2;

	if (!net_ip_compare(&rec1->ip, &rec2->ip))
		return 1;

	return (int)rec1->port - (int)rec2->port;
}

struct login_proxy_state *login_proxy_state_init(const char *notify_path)
{
	struct login_proxy_state *state;

	state = i_new(struct login_proxy_state, 1);
	state->pool = pool_alloconly_create("login proxy state", 1024);
	state->hash = hash_table_create(default_pool, state->pool, 0,
					login_proxy_record_hash,
					login_proxy_record_cmp);
	state->notify_path = p_strdup(state->pool, notify_path);
	state->notify_fd = -1;
	return state;
}

void login_proxy_state_deinit(struct login_proxy_state **_state)
{
	struct login_proxy_state *state = *_state;

	*_state = NULL;

	if (state->notify_fd != -1) {
		if (close(state->notify_fd) < 0)
			i_error("close(%s) failed: %m", state->notify_path);
	}
	hash_table_destroy(&state->hash);
	pool_unref(&state->pool);
	i_free(state);
}

struct login_proxy_record *
login_proxy_state_get(struct login_proxy_state *state,
		      const struct ip_addr *ip, unsigned int port)
{
	struct login_proxy_record *rec, key;

	memset(&key, 0, sizeof(key));
	key.ip = *ip;
	key.port = port;

	rec = hash_table_lookup(state->hash, &key);
	if (rec == NULL) {
		rec = p_new(state->pool, struct login_proxy_record, 1);
		rec->ip = *ip;
		rec->port = port;
		hash_table_insert(state->hash, rec, rec);
	}
	return rec;
}

static int login_proxy_state_notify_open(struct login_proxy_state *state)
{
	if (state->notify_fd_broken)
		return -1;

	state->notify_fd = open(state->notify_path, O_WRONLY);
	if (state->notify_fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", state->notify_path);
		state->notify_fd_broken = TRUE;
		return -1;
	}
	fd_set_nonblock(state->notify_fd, TRUE);
	return 0;
}

void login_proxy_state_notify(struct login_proxy_state *state,
			      const char *user)
{
	unsigned int len;
	ssize_t ret;

	if (state->notify_fd == -1) {
		if (login_proxy_state_notify_open(state) < 0)
			return;
	}

	T_BEGIN {
		const char *cmd;

		cmd = t_strconcat(str_tabescape(user), "\n", NULL);
		len = strlen(cmd);
		ret = write(state->notify_fd, cmd, len);
	} T_END;

	if (ret != (ssize_t)len) {
		if (ret < 0)
			i_error("write(%s) failed: %m", state->notify_path);
		else {
			i_error("write(%s) wrote partial update",
				state->notify_path);
		}
	}
}

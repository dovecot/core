/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "listener.h"

#include <stdlib.h>
#include <unistd.h>

static void resolve_ip(const char *set_name, const char *name,
		       struct ip_addr *ip, unsigned int *port)
{
	struct ip_addr *ip_list;
	const char *p;
	unsigned int ips_count;
	int ret;

	if (*name == '\0') {
                /* defaults to "*" or "[::]" */
		ip->family = 0;
		return;
	}

	if (name[0] == '[') {
		/* IPv6 address */
		p = strchr(name, ']');
		if (p == NULL) {
			i_fatal("%s: Missing ']' in address %s",
				set_name, name);
		}
		name = t_strdup_until(name+1, p);

		p++;
		if (*p == '\0')
			p = NULL;
		else if (*p != ':') {
			i_fatal("%s: Invalid data after ']' in address %s",
				set_name, name);
		}
	} else {
		p = strrchr(name, ':');
		if (p != NULL)
			name = t_strdup_until(name, p);
	}

	if (p != NULL) {
		if (!is_numeric(p+1, '\0')) {
			i_fatal("%s: Invalid port in address %s",
				set_name, name);
		}
		*port = atoi(p+1);
	}

	if (strcmp(name, "*") == 0) {
		/* IPv4 any */
		net_get_ip_any4(ip);
		return;
	}

	if (strcmp(name, "::") == 0) {
		/* IPv6 any */
		net_get_ip_any6(ip);
		return;
	}

	/* Return the first IP if there happens to be multiple. */
	ret = net_gethostbyname(name, &ip_list, &ips_count);
	if (ret != 0) {
		i_fatal("%s: Can't resolve address %s: %s",
			set_name, name, net_gethosterror(ret));
	}

	if (ips_count < 1)
		i_fatal("%s: No IPs for address: %s", set_name, name);

	*ip = ip_list[0];
}

static void
check_conflicts_set(const struct settings *set, const struct ip_addr *ip,
		    unsigned int port, const char *name1, const char *name2)
{
	const struct listener *listens = NULL;
	unsigned int i, count;

	if (array_is_created(&set->listens))
		listens = array_get(&set->listens, &count);
	else
		count = 0;
	for (i = 0; i < count; i++) {
		if (listens[i].fd <= 0 || listens[i].port != port ||
		    !net_ip_compare(&listens[i].ip, ip))
			continue;

		i_fatal("Protocols %s and %s are listening in same ip/port",
			name1, name2);
	}

	if (array_is_created(&set->ssl_listens))
		listens = array_get(&set->ssl_listens, &count);
	else
		count = 0;
	for (i = 0; i < count; i++) {
		if (listens[i].fd <= 0 || listens[i].port != port ||
		    !net_ip_compare(&listens[i].ip, ip))
			continue;

		i_fatal("Protocols %ss and %ss are listening in same ip/port",
			name1, name2);
	}
}

static void check_conflicts(const struct ip_addr *ip, unsigned int port,
			    const char *proto)
{
	struct server_settings *server;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL) {
			check_conflicts_set(server->imap, ip, port,
					    "imap", proto);
		}
		if (server->pop3 != NULL) {
			check_conflicts_set(server->pop3, ip, port,
					    "pop3", proto);
		}
	}
}

static void
listener_init(const char *set_name, const char *listen_list,
	      unsigned int default_port, ARRAY_TYPE(listener) *listens_arr)
{
	const char *const *tmp;
	struct listener l, *listens;
	unsigned int i, count;

	if (!array_is_created(listens_arr))
		i_array_init(listens_arr, 4);

	listens = array_get_modifiable(listens_arr, &count);
	for (i = 0; i < count; i++)
		listens[i].wanted = FALSE;

	memset(&l, 0, sizeof(l));
	l.fd = -1;
	l.wanted = TRUE;

	for (tmp = t_strsplit_spaces(listen_list, ", "); *tmp != NULL; tmp++) {
		l.port = default_port;
		resolve_ip(set_name, *tmp, &l.ip, &l.port);

		/* see if it already exists */
		for (i = 0; i < count; i++) {
			if (listens[i].port == l.port &&
			    net_ip_compare(&listens[i].ip, &l.ip)) {
				listens[i].wanted = TRUE;
				break;
			}
		}

		if (i == count) {
			array_append(listens_arr, &l, 1);
			listens = array_get_modifiable(listens_arr, &count);
		}
	}

	/* close unwanted fds */
	for (i = 0; i < count; ) {
		if (listens[i].wanted)
			i++;
		else {
			if (listens[i].fd > 0) {
				if (close(listens[i].fd) < 0)
					i_error("close(listener) failed: %m");
			}
			array_delete(listens_arr, i, 1);
			listens = array_get_modifiable(listens_arr, &count);
		}
	}
}

static void listener_close_fds(ARRAY_TYPE(listener) *listens_arr)
{
	const struct listener *listens;
	unsigned int i, count;

	if (!array_is_created(listens_arr))
		return;

	listens = array_get(listens_arr, &count);
	for (i = 0; i < count; i++) {
		if (listens[i].fd > 0) {
			if (close(listens[i].fd) < 0)
				i_error("close(listener) failed: %m");
		}
	}
	array_free(listens_arr);
}

static void listen_parse_and_close_unneeded(struct settings *set)
{
	const char *const *proto;
	unsigned int default_port;
	bool nonssl_listen = FALSE, ssl_listen = FALSE;

	if (set == NULL)
		return;

	/* register wanted protocols */
        proto = t_strsplit_spaces(set->protocols, " ");
	for (; *proto != NULL; proto++) {
		if (strcasecmp(*proto, "imap") == 0) {
			if (set->protocol == MAIL_PROTOCOL_IMAP)
				nonssl_listen = TRUE;
		} else if (strcasecmp(*proto, "imaps") == 0) {
			if (set->protocol == MAIL_PROTOCOL_IMAP &&
			    !set->ssl_disable)
				ssl_listen = TRUE;
		} else if (strcasecmp(*proto, "pop3") == 0) {
			if (set->protocol == MAIL_PROTOCOL_POP3)
				nonssl_listen = TRUE;
		} else if (strcasecmp(*proto, "pop3s") == 0) {
			if (set->protocol == MAIL_PROTOCOL_POP3 &&
			    !set->ssl_disable)
				ssl_listen = TRUE;
		}
	}

	if (!nonssl_listen)
		listener_close_fds(&set->listens);
	else {
		default_port = set->protocol == MAIL_PROTOCOL_IMAP ? 143 : 110;
		listener_init("listen", set->listen, default_port,
			      &set->listens);
	}
	if (!ssl_listen)
		listener_close_fds(&set->ssl_listens);
	else {
		default_port = set->protocol == MAIL_PROTOCOL_IMAP ? 993 : 995;
		listener_init("ssl_listen", *set->ssl_listen != '\0' ?
			      set->ssl_listen : set->listen, default_port,
			      &set->ssl_listens);
	}
}

static void listen_copy_old(struct settings *old_set, struct settings *new_set)
{
	if (old_set == NULL || new_set == NULL) {
		if (old_set != NULL) {
			listener_close_fds(&old_set->listens);
			listener_close_fds(&old_set->ssl_listens);
		}
		return;
	}

	i_assert(!array_is_created(&new_set->listens));
	i_assert(!array_is_created(&new_set->ssl_listens));

	new_set->listens = old_set->listens;
	new_set->ssl_listens = old_set->ssl_listens;

	old_set->listens.arr.buffer = NULL;
	old_set->ssl_listens.arr.buffer = NULL;
}

static void
listener_array_listen_missing(const char *proto,
			      ARRAY_TYPE(listener) *listens_arr, bool retry)
{
	struct listener *listens;
	unsigned int i, j, count;

	if (!array_is_created(listens_arr))
		return;

	listens = array_get_modifiable(listens_arr, &count);
	for (i = 0; i < count; i++) {
		if (listens[i].fd > 0)
			continue;

		for (j = 0; j < 10; j++) {
			listens[i].fd = net_listen(&listens[i].ip,
						   &listens[i].port, 128);
			if (listens[i].fd != -1)
				break;

			if (errno == EADDRINUSE) {
				/* retry */
			} else if (errno == EINTR &&
				   io_loop_is_running(ioloop)) {
				/* SIGHUPing sometimes gets us here.
				   we don't want to die. */
			} else {
				/* error */
				break;
			}

			check_conflicts(&listens[i].ip, listens[i].port, proto);
			if (!retry)
				break;

			/* wait a while and try again. we're SIGHUPing
			   so we most likely just closed it ourself.. */
			sleep(1);
		}

		if (listens[i].fd == -1) {
			i_fatal("listen(%s, %d) failed: %m",
				net_ip2addr(&listens[i].ip), listens[i].port);
		}
		net_set_nonblock(listens[i].fd, TRUE);
		fd_close_on_exec(listens[i].fd, TRUE);
	}
}

static void
listener_listen_missing(struct settings *set, const char *proto, bool retry)
{
	listener_array_listen_missing(proto, &set->listens, retry);
	listener_array_listen_missing(t_strconcat(proto, "s", NULL),
				      &set->ssl_listens, retry);
}

void listeners_open_fds(struct server_settings *old_set, bool retry)
{
	struct server_settings *server;

	for (server = settings_root; server != NULL; server = server->next) {
		if (old_set != NULL) {
			listen_copy_old(old_set->imap, server->imap);
			listen_copy_old(old_set->pop3, server->pop3);
		}
		listen_parse_and_close_unneeded(server->imap);
		listen_parse_and_close_unneeded(server->pop3);

		if (old_set != NULL)
			old_set = old_set->next;
	}

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL)
			listener_listen_missing(server->imap, "imap", retry);
		if (server->pop3 != NULL)
			listener_listen_missing(server->pop3, "pop3", retry);
	}
}

void listeners_close_fds(void)
{
	struct server_settings *server;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL) {
			listener_close_fds(&server->imap->listens);
			listener_close_fds(&server->imap->ssl_listens);
		}
		if (server->pop3 != NULL) {
			listener_close_fds(&server->pop3->listens);
			listener_close_fds(&server->pop3->ssl_listens);
		}
	}
}

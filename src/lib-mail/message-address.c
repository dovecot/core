/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "message-tokenize.h"
#include "message-address.h"

static struct message_address *
new_address(pool_t pool, struct message_address ***next_addr)
{
	struct message_address *addr;

	addr = p_new(pool, struct message_address, 1);

	**next_addr = addr;
	*next_addr = &addr->next;

	return addr;
}

struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size,
		      unsigned int max_addresses)
{
	static const enum message_token stop_tokens_init[] =
		{ ',', '@', '<', ':', TOKEN_LAST };
	static const enum message_token stop_tokens_group[] =
		{ ',', '@', '<', ';', TOKEN_LAST };
	static const enum message_token stop_tokens_domain[] =
		{ ',', '<', TOKEN_LAST };
	static const enum message_token stop_tokens_domain_group[] =
		{ ',', '<', ';', TOKEN_LAST };
	static const enum message_token stop_tokens_post_addr[] =
		{ ',', TOKEN_LAST };
	static const enum message_token stop_tokens_post_addr_group[] =
		{ ',', ';', TOKEN_LAST };
	static const enum message_token stop_tokens_addr_route[] =
		{ ':', '>', TOKEN_LAST };
	static const enum message_token stop_tokens_addr_mailbox[] =
		{ '@', '>', TOKEN_LAST };
	static const enum message_token stop_tokens_addr_domain[] =
		{ '>', TOKEN_LAST };

	struct message_address *first_addr, **next_addr, *addr;
	struct message_tokenizer *tok;
	const enum message_token *stop_tokens;
	enum message_token token;
	string_t *mailbox, *domain, *route, *name, *comment, *next_phrase;
	size_t len;
	int ingroup, stop;

	if (size == 0)
		return NULL;

	first_addr = NULL;
	next_addr = &first_addr;

	/* 1) name <@route:mailbox@domain>, ...
	   2) mailbox@domain (name), ...
	   3) group: name <box@domain>, box2@domain2 (name2), ... ;, ...

	   ENVELOPE wants groups to be stored like (NIL, NIL, group, NIL),
	   ..., (NIL, NIL, NIL, NIL)
	*/
	tok = message_tokenize_init(data, size, NULL, NULL);
	message_tokenize_skip_comments(tok, FALSE);
        message_tokenize_dot_token(tok, FALSE);

	t_push();
	mailbox = t_str_new(128);
	domain = t_str_new(256);
	route = t_str_new(128);
	name = t_str_new(256);
	comment = t_str_new(256);

	ingroup = FALSE; len = 0;
	stop_tokens = stop_tokens_init;

	if (max_addresses == 0)
		max_addresses = (unsigned int)-1;

	next_phrase = mailbox; stop = FALSE;
	while (!stop && max_addresses > 0) {
		if (next_phrase == name && str_len(name) > 0) {
			/* continuing previously started name,
			   separate it from us with space */
			str_append_c(name, ' ');
			len = str_len(name);
		} else {
			len = 0;
		}
		message_tokenize_get_string(tok, next_phrase, comment,
					    stop_tokens);

		if (next_phrase == name && len > 0 && len == str_len(name)) {
			/* nothing appeneded, remove the space */
			str_truncate(name, len-1);
		}

		token = message_tokenize_get(tok);
		switch (token) {
		case TOKEN_LAST:
		case ',':
		case ';':
			/* end of address */
			if (str_len(mailbox) > 0 || str_len(domain) > 0 ||
			    str_len(route) > 0 || str_len(name) > 0) {
				addr = new_address(pool, &next_addr);
				max_addresses--;
				addr->mailbox = p_strdup(pool, str_c(mailbox));
				addr->domain = str_len(domain) == 0 ? NULL :
					p_strdup(pool, str_c(domain));
				addr->route = str_len(route) == 0 ? NULL :
					p_strdup(pool, str_c(route));
				addr->name = next_phrase == name ?
					p_strdup_empty(pool, str_c(name)) :
					p_strdup_empty(pool, str_c(comment));
			}

			if (ingroup && token == ';') {
				/* end of group - add end of group marker */
				ingroup = FALSE;
				(void)new_address(pool, &next_addr);
				max_addresses--;
			}

			if (token == TOKEN_LAST) {
				stop = TRUE;
				break;
			}

			stop_tokens = ingroup ? stop_tokens_group :
				stop_tokens_init;

			str_truncate(mailbox, 0);
			str_truncate(domain, 0);
			str_truncate(route, 0);
			str_truncate(name, 0);
			str_truncate(comment, 0);

			next_phrase = mailbox;
			break;
		case '@':
			/* domain part comes next */
			next_phrase = domain;
			stop_tokens = ingroup ? stop_tokens_domain_group :
				stop_tokens_domain;
			break;
		case '<':
			/* route-addr */

			/* mailbox/domain name so far has actually
			   been the real name */
			str_append_str(name, mailbox);
			str_truncate(mailbox, 0);

			if (str_len(domain) > 0) {
                                str_append_c(name, '@');
				str_append_str(name, domain);
				str_truncate(domain, 0);
			}

			/* mailbox */
			message_tokenize_get_string(tok, mailbox, NULL,
						    stop_tokens_addr_mailbox);

			if (message_tokenize_get(tok) == '@' &&
			    str_len(mailbox) == 0) {
				/* route is given */
				message_tokenize_get_string(tok,
					route, NULL, stop_tokens_addr_route);

				if (message_tokenize_get(tok) == ':') {
					/* mailbox comes next */
					message_tokenize_get_string(tok,
						mailbox, NULL,
						stop_tokens_addr_mailbox);
				}
			}

			if (message_tokenize_get(tok) == '@') {
				/* domain */
				message_tokenize_get_string(tok,
					domain, NULL, stop_tokens_addr_domain);
			}

			token = message_tokenize_get(tok);
			i_assert(token == '>' || token == TOKEN_LAST);

			next_phrase = name;
			stop_tokens = ingroup ? stop_tokens_post_addr_group :
				stop_tokens_post_addr;
			break;
		case ':':
			/* beginning of group */
			addr = new_address(pool, &next_addr);
			max_addresses--;
			addr->name = p_strdup(pool, str_c(mailbox));

			str_truncate(mailbox, 0);
			str_truncate(comment, 0);

			ingroup = TRUE;
			stop_tokens = stop_tokens_group;
			break;
		default:
			i_unreached();
			break;
		}
	}

	if (ingroup)
		(void)new_address(pool, &next_addr);

	t_pop();
	message_tokenize_deinit(tok);

	return first_addr;
}

void message_address_write(string_t *str, const struct message_address *addr)
{
	int first = TRUE, in_group = FALSE;

	/* a) mailbox@domain
	   b) name <@route:mailbox@domain>
	   c) group: .. ; */

	while (addr != NULL) {
		if (first)
			first = FALSE;
		else
			str_append(str, ", ");

		if (addr->mailbox == NULL && addr->domain == NULL) {
			if (!in_group) {
				if (addr->name != NULL)
					str_append(str, addr->name);
				str_append(str, ": ");
				first = TRUE;
			} else {
				i_assert(addr->name == NULL);

				/* cut out the ", " */
				str_truncate(str, str_len(str)-2);
				str_append_c(str, ';');
			}

			in_group = !in_group;
		} else if ((addr->name == NULL || *addr->name == '\0') &&
			   addr->route == NULL) {
			i_assert(addr->mailbox != NULL);
			i_assert(addr->domain != NULL);

			str_append(str, addr->mailbox);
			str_append_c(str, '@');
			str_append(str, addr->domain);
		} else {
			i_assert(addr->mailbox != NULL);
			i_assert(addr->domain != NULL);

			if (addr->name != NULL) {
				str_append(str, addr->name);
				str_append_c(str, ' ');
			}
			str_append_c(str, '<');
			if (addr->route != NULL) {
				str_append_c(str, '@');
				str_append(str, addr->route);
				str_append_c(str, ':');
			}
			str_append(str, addr->mailbox);
			str_append_c(str, '@');
			str_append(str, addr->domain);
			str_append_c(str, '>');
		}
	}
}

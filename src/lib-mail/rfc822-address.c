/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "rfc822-tokenize.h"
#include "rfc822-address.h"

static Rfc822Address *new_address(Pool pool, Rfc822Address ***next_addr)
{
	Rfc822Address *addr;

	addr = p_new(pool, Rfc822Address, 1);

	**next_addr = addr;
	*next_addr = &addr->next;

	return addr;
}

static int read_until(const Rfc822Token *tokens, const char *stop_tokens,
		      String *comment)
{
	char *c_str;
	int i, pos;

	/* find the stop token */
	for (i = 0; tokens[i].token != 0; i++) {
		if (strchr(stop_tokens, tokens[i].token) != NULL)
			break;

		if (tokens[i].token == '(' && comment != NULL) {
			/* save comment */
			if (str_len(comment) > 0)
				str_append_c(comment, ' ');
			pos = str_len(comment);

			str_append_n(comment, tokens[i].ptr, tokens[i].len);
			c_str = str_c_modifyable(comment);

			str_remove_escapes(c_str + pos);
			str_truncate(comment, strlen(c_str));
		}
	}

	return i;
}

static void read_until_get(const Rfc822Token **tokens, const char *stop_tokens,
			   String *phrase, String *comment)
{
	const char *value;
	int count;

	count = read_until(*tokens, stop_tokens, comment);
	if (count > 0) {
		value = rfc822_tokens_get_value(*tokens, count);
		str_append(phrase, value);

		*tokens += count;
	}
}

Rfc822Address *rfc822_address_parse(Pool pool, const char *str)
{
	Rfc822Address *first_addr, **next_addr, *addr;
	String *mailbox, *domain, *route, *name, *comment, *next_phrase;
	const Rfc822Token *tokens;
	const char *list, *value;
	int ingroup, stop, count;

	if (str == NULL || *str == '\0')
		return NULL;

	first_addr = NULL;
	next_addr = &first_addr;

	/* 1) name <@route:mailbox@domain>, ...
	   2) mailbox@domain (name), ...
	   3) group: name <box@domain>, box2@domain2 (name2), ... ;, ...

	   ENVELOPE wants groups to be stored like (NIL, NIL, group, NIL),
	   ..., (NIL, NIL, NIL, NIL)
	*/
	tokens = rfc822_tokenize(str, NULL, NULL, NULL);

	t_push();
	mailbox = t_str_new(128);
	domain = t_str_new(128);
	route = t_str_new(128);
	name = t_str_new(128);
	comment = t_str_new(128);

	ingroup = FALSE;
	list = ",@<:";

	next_phrase = mailbox; stop = FALSE;
	while (!stop) {
		count = read_until(tokens, list, comment);
		if (count > 0) {
			if ((tokens[count].token == '<' ||
			     next_phrase == name) && str_len(next_phrase) > 0) {
				/* continuing previously started name,
				   separate it from us with space */
				str_append_c(next_phrase, ' ');
			}

			value = rfc822_tokens_get_value(tokens, count);
			str_append(next_phrase, value);
			tokens += count;
		}

		switch (tokens->token) {
		case 0:
		case ',':
		case ';':
			/* end of address */
			if (str_len(mailbox) > 0 || str_len(domain) > 0 ||
			    str_len(route) > 0 || str_len(name) > 0) {
				addr = new_address(pool, &next_addr);
				addr->mailbox = p_strdup(pool, str_c(mailbox));
				addr->domain = str_len(domain) == 0 ? NULL :
					p_strdup(pool, str_c(domain));
				addr->route = str_len(route) == 0 ? NULL :
					p_strdup(pool, str_c(route));
				addr->name = next_phrase == name ?
					p_strdup(pool, str_c(name)) :
					p_strdup(pool, str_c(comment));
			}

			if (ingroup && tokens->token == ';') {
				/* end of group - add end of group marker */
				ingroup = FALSE;
				(void)new_address(pool, &next_addr);
			}

			if (tokens->token == 0) {
				stop = TRUE;
				break;
			}

			list = ingroup ? ",@<;" :  ",@<:";

			str_truncate(mailbox, 0);
			str_truncate(domain, 0);
			str_truncate(route, 0);
			str_truncate(name, 0);
			str_truncate(comment, 0);

			tokens++;
			next_phrase = mailbox;
			break;
		case '@':
			/* domain part comes next */
			tokens++;
			next_phrase = domain;
			list = ingroup ? ",<;" : ",<";
			break;
		case '<':
			/* route-addr */
			tokens++;

			/* mailbox/domain name so far has actually
			   been the real name */
			str_append_str(name, mailbox);
			if (str_len(domain) > 0) {
                                str_append_c(name, '@');
				str_append_str(name, domain);
			}

			str_truncate(mailbox, 0);
			str_truncate(domain, 0);

			read_until_get(&tokens, "@>", mailbox, NULL);
			if (tokens->token == '@' && str_len(mailbox) == 0) {
				/* route is given */
				tokens++;
				read_until_get(&tokens, ":>", route, NULL);
				if (tokens->token == ':') {
					/* mailbox comes next */
					tokens++;
					read_until_get(&tokens, "@>",
						       mailbox, NULL);
				}
			}

			if (tokens->token == '@') {
				tokens++;
				read_until_get(&tokens, ">", domain, NULL);
			}

			if (tokens->token == '>')
				tokens++;

			next_phrase = name;
			list = ingroup ? ",;" : ",";
			break;
		case ':':
			/* beginning of group */
			addr = new_address(pool, &next_addr);
			addr->name = p_strdup(pool, str_c(mailbox));

			str_truncate(mailbox, 0);
			tokens++;

			ingroup = TRUE;
			list = ",@<;";
			break;
		}
	}

	if (ingroup)
		(void)new_address(pool, &next_addr);

	t_pop();
	return first_addr;
}


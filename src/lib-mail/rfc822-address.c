/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "temp-string.h"
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
		      TempString *comment)
{
	int i, pos;

	/* find the stop token */
	for (i = 0; tokens[i].token != 0; i++) {
		if (strchr(stop_tokens, tokens[i].token) != NULL)
			break;

		if (tokens[i].token == '(') {
			/* save comment */
			if (comment->len > 0)
				t_string_append_c(comment, ' ');
			pos = comment->len;

			t_string_append_n(comment, tokens[i].ptr,
					  tokens[i].len);

			string_remove_escapes(comment->str + pos);
			comment->len = strlen(comment->str);
		}
	}

	return i;
}

static void read_until_get(const Rfc822Token **tokens, const char *stop_tokens,
			   TempString *phrase, TempString *comment)
{
	const char *value;
	int count;

	count = read_until(*tokens, stop_tokens, comment);
	if (count > 0) {
		value = rfc822_tokens_get_value(*tokens, count, FALSE);
		t_string_append(phrase, value);

		*tokens += count;
	}
}

Rfc822Address *rfc822_address_parse(Pool pool, const char *str)
{
	Rfc822Address *first_addr, **next_addr, *addr;
	TempString *mailbox, *domain, *route, *name, *comment, *next_phrase;
	const Rfc822Token *tokens;
	const char *list, *value;
	int ingroup, stop, count, spaces;

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
	mailbox = t_string_new(128);
	domain = t_string_new(128);
	route = t_string_new(128);
	name = t_string_new(128);
	comment = t_string_new(128);

	ingroup = FALSE;
	list = ",@<:";

	next_phrase = mailbox; stop = FALSE;
	while (!stop) {
		count = read_until(tokens, list, comment);
		if (count > 0) {
			/* put spaces around tokens if we're parsing name */
			spaces = tokens[count].token == '<' ||
				next_phrase == name;
			if (spaces && next_phrase->len > 0)
				t_string_append_c(next_phrase, ' ');

			value = rfc822_tokens_get_value(tokens, count, spaces);
			t_string_append(next_phrase, value);
			tokens += count;
		}

		switch (tokens->token) {
		case 0:
		case ',':
		case ';':
			/* end of address */
			if (mailbox->len > 0 || domain->len > 0 ||
			    route->len > 0 || name->len > 0) {
				addr = new_address(pool, &next_addr);
				addr->mailbox = p_strdup(pool, mailbox->str);
				addr->domain = domain->len == 0 ? NULL :
					p_strdup(pool, domain->str);
				addr->route = route->len == 0 ? NULL :
					p_strdup(pool, route->str);
				addr->name = next_phrase == name ?
					p_strdup(pool, name->str) :
					p_strdup(pool, comment->str);
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

			t_string_truncate(mailbox, 0);
			t_string_truncate(domain, 0);
			t_string_truncate(route, 0);
			t_string_truncate(name, 0);
			t_string_truncate(comment, 0);

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
			t_string_append(name, mailbox->str);
			if (domain->len > 0) {
                                t_string_append_c(name, '@');
				t_string_append(name, domain->str);
			}

			t_string_truncate(mailbox, 0);
			t_string_truncate(domain, 0);

			read_until_get(&tokens, "@>", mailbox, NULL);
			if (tokens->token == '@' && mailbox->len == 0) {
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
			addr->name = p_strdup(pool, mailbox->str);

			t_string_truncate(mailbox, 0);
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


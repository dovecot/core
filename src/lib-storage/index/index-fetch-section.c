/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "temp-string.h"
#include "iobuffer.h"
#include "rfc822-tokenize.h"
#include "imap-message-send.h"
#include "index-storage.h"
#include "index-fetch.h"

#include <ctype.h>
#include <unistd.h>

ImapCacheField index_fetch_body_get_cache(const char *section)
{
	if (*section >= '0' && *section <= '9')
		return IMAP_CACHE_MESSAGE_PART | IMAP_CACHE_MESSAGE_OPEN;

	if (*section == '\0' || strcasecmp(section, "TEXT") == 0) {
		/* no IMAP_CACHE_MESSAGE_BODY_SIZE, so that we don't
		   uselessly check it when we want to read partial data */
		return IMAP_CACHE_MESSAGE_OPEN;
	}

	if (strncasecmp(section, "HEADER", 6) == 0 ||
	    strcasecmp(section, "MIME") == 0)
		return IMAP_CACHE_MESSAGE_HDR_SIZE | IMAP_CACHE_MESSAGE_OPEN;

	/* error */
	return 0;
}

/* fetch BODY[] or BODY[TEXT] */
static int fetch_body(MailIndexRecord *rec, MailFetchBodyData *sect,
		      FetchData *data, int fetch_header)
{
	MessageSize size;
	const char *msg, *str;
	int fd;

	if (!imap_msgcache_get_rfc822_partial(data->cache, rec->uid,
					      sect->skip, sect->max_size,
					      fetch_header, &size, &msg, &fd)) {
		i_error("Couldn't get BODY[] for UID %u (index %s)",
			rec->uid, data->index->filepath);
		return FALSE;
	}

	str = t_strdup_printf("{%lu}\r\n", (unsigned long) size.virtual_size);
	(void)io_buffer_send(data->outbuf, str, strlen(str));

	(void)imap_message_send(data->outbuf, msg, fd, &size,
				0, sect->max_size);
	return TRUE;
}

static char *const *get_fields_array(const char *fields)
{
	char **field_list, **field;

	while (*fields == ' ')
		fields++;
	if (*fields == '(')
		fields++;

	field_list = (char **) t_strsplit(fields, " )");

	/* array ends at ")" element */
	for (field = field_list; *field != NULL; field++) {
		if (strcasecmp(*field, ")") == 0)
			*field = NULL;
	}

	return field_list;
}

static int header_match(char *const *fields, const char *data, size_t size)
{
	const char *field, *data_start, *data_end;

	i_assert(size > 0);

	data_start = data;
	data_end = data + size;

	for (; *fields != NULL; fields++) {
		field = *fields;
		if (*field == '\0')
			continue;

		for (data = data_start; data != data_end; data++) {
			/* field has been uppercased long time ago while
			   parsing FETCH command */
			if (i_toupper(*data) != *field)
				break;

			field++;
			if (*field == '\0') {
				/* "field : value" is valid */
				while (data+1 != data_end && IS_LWSP(data[1]))
					data++;

				if (data+1 != data_end && data[1] == ':')
					return TRUE;
				break;
			}
		}
	}

	return FALSE;
}

static int header_match_not(char *const *fields, const char *data, size_t size)
{
	return !header_match(fields, data, size);
}

static int header_match_mime(char *const *fields __attr_unused__,
			     const char *data, size_t size)
{
	if (size > 8 && strncasecmp(data, "Content-", 8) == 0)
		return TRUE;

	if (size >= 13 && strncasecmp(data, "Mime-Version:", 13) == 0)
		return TRUE;

	return FALSE;
}

/* Store headers into dest, returns number of bytes written. */
static unsigned int
fetch_header_fields(const char *msg, size_t size,
		    char *dest, char *const *fields,
		    int (*match_func) (char *const *, const char *, size_t))
{
	const char *msg_start, *msg_end, *cr;
	char *dest_start;
	unsigned int i;
	int matched;

	dest_start = dest;

	/* parse fields uppercased into array - no error checking */
	msg_start = msg;
	msg_end = msg + size;

	cr = NULL; matched = FALSE;
	for (; msg != msg_end; msg++) {
		if (*msg == '\r')
			cr = msg;
		else if (*msg == '\n') {
			if (!matched && msg != msg_start &&
			    !IS_LWSP(*msg_start)) {
				matched = match_func(fields, msg_start,
						     (size_t) (msg-msg_start));
			}

			if (matched) {
				if (cr == msg-1) {
					/* contains CR+LF, copy them */
					i = (unsigned int) (msg-msg_start)+1;
					memcpy(dest, msg_start, i);
					dest += i;
				} else {
					/* copy line without LF, appending
					   CR+LF afterwards */
					i = (unsigned int) (msg-msg_start);
					memcpy(dest, msg_start, i);
					dest += i;

					*dest++ = '\r';
					*dest++ = '\n';
				}

				/* see if it continues in next line */
				matched = msg+1 != msg_end && IS_LWSP(msg[1]);
			}

			msg_start = msg+1;
		}
	}

	/* headers should always end with \n\n, so we don't need to
	   check the last line here */

	return (unsigned int) (dest - dest_start);
}

/* fetch wanted headers from given data */
static void fetch_header_from(const char *msg, int fd, MessageSize *size,
			      const char *section, MailFetchBodyData *sect,
			      FetchData *data)
{
	const char *str;
	char *dest;
	unsigned int len;

	/* HEADER, MIME, HEADER.FIELDS (list), HEADER.FIELDS.NOT (list) */

	if (strcasecmp(section, "HEADER") == 0) {
		/* all headers */
		str = t_strdup_printf("{%lu}\r\n",
				      (unsigned long) size->virtual_size);
		(void)io_buffer_send(data->outbuf, str, strlen(str));
		(void)imap_message_send(data->outbuf, msg, fd,
					size, sect->skip, sect->max_size);
		return;
	}

	/* partial headers - copy the wanted fields into temporary memory.
	   Insert missing CRs on the way. */
	t_push();
	dest = t_malloc(size->virtual_size);

	if (strncasecmp(section, "HEADER.FIELDS ", 14) == 0) {
		len = fetch_header_fields(msg, size->physical_size, dest,
					  get_fields_array(section + 14),
					  header_match);
	} else if (strncasecmp(section, "HEADER.FIELDS.NOT ", 18) == 0) {
		len = fetch_header_fields(msg, size->physical_size, dest,
					  get_fields_array(section + 18),
					  header_match_not);
	} else if (strcasecmp(section, "MIME") == 0) {
		/* Mime-Version + Content-* fields */
		len = fetch_header_fields(msg, size->physical_size, dest,
					  NULL, header_match_mime);
	} else {
		/* error */
		len = 0;
	}

	i_assert(len <= size->virtual_size);

	if ((off_t) len <= sect->skip)
		len = 0;
	else {
		dest += sect->skip;
		len -= sect->skip;

		if (sect->max_size > 0 && len > sect->max_size)
			len = sect->max_size;
	}

	str = t_strdup_printf("{%u}\r\n", len);
	io_buffer_send(data->outbuf, str, strlen(str));
	if (len > 0) io_buffer_send(data->outbuf, dest, len);

	t_pop();
}

/* fetch BODY[HEADER...] */
static int fetch_header(MailIndexRecord *rec, MailFetchBodyData *sect,
			FetchData *data)
{
	MessageSize hdr_size;
	const char *msg;
	int fd;

	if (!imap_msgcache_get_rfc822(data->cache, rec->uid,
				      &hdr_size, NULL, &msg, &fd))
		return FALSE;

	fetch_header_from(msg, fd, &hdr_size, sect->section, sect, data);
	return TRUE;
}

/* Find MessagePart for section (eg. 1.3.4) */
static MessagePart *part_find(MailIndexRecord *rec, MailFetchBodyData *sect,
			      FetchData *data, const char **section)
{
	MessagePart *part;
	const char *path;
	int num;

	part = imap_msgcache_get_parts(data->cache, rec->uid);

	path = sect->section;
	while (*path >= '0' && *path <= '9' && part != NULL) {
		/* get part number */
		num = 0;
		while (*path != '\0' && *path != '.') {
			if (*path < '0' || *path > '9')
				return NULL;
			num = num*10 + *path - '0';
			path++;
		}

		if (*path == '.')
			path++;

		if (part->multipart) {
			/* find the part */
			part = part->children;
			for (; num > 1 && part != NULL; num--)
				part = part->next;
		} else {
			/* only 1 allowed with non-multipart messages */
			if (num != 1)
				return NULL;
		}
	}

	*section = path;
	return part;
}

/* fetch BODY[1.2] or BODY[1.2.TEXT] */
static int fetch_part_body(MessagePart *part, unsigned int uid,
			   MailFetchBodyData *sect, FetchData *data)
{
	const char *msg, *str;
	off_t skip_pos;
	int fd;

	if (!imap_msgcache_get_data(data->cache, uid, &msg, &fd, NULL))
		return FALSE;

	/* jump to beginning of wanted data */
	skip_pos = (off_t) (part->pos.physical_pos +
			    part->header_size.physical_size);
	msg += skip_pos;
	if (fd != -1 && lseek(fd, skip_pos, SEEK_CUR) == (off_t)-1)
		fd = -1;

	str = t_strdup_printf("{%lu}\r\n",
			      (unsigned long) part->body_size.virtual_size);
	(void)io_buffer_send(data->outbuf, str, strlen(str));

	/* FIXME: potential performance problem with big messages:
	   FETCH BODY[1]<100000..1024>, hopefully no clients do this */
	(void)imap_message_send(data->outbuf, msg, -1, &part->body_size,
				sect->skip, sect->max_size);
	return TRUE;
}

/* fetch BODY[1.2.MIME|HEADER...] */
static int fetch_part_header(MessagePart *part, unsigned int uid,
			     const char *section, MailFetchBodyData *sect,
			     FetchData *data)
{
	const char *msg;

	if (!imap_msgcache_get_data(data->cache, uid, &msg, NULL, NULL))
		return FALSE;

	fetch_header_from(msg + part->pos.physical_pos, -1,
			  &part->header_size, section, sect, data);
	return TRUE;
}

static int fetch_part(MailIndexRecord *rec, MailFetchBodyData *sect,
		      FetchData *data)
{
	MessagePart *part;
	const char *section;

	part = part_find(rec, sect, data, &section);
	if (part == NULL)
		return FALSE;

	if (*section == '\0' || strcasecmp(section, "TEXT") == 0)
		return fetch_part_body(part, rec->uid, sect, data);

	if (strncasecmp(section, "HEADER", 6) == 0)
		return fetch_part_header(part, rec->uid, section, sect, data);
	if (strcasecmp(section, "MIME") == 0)
		return fetch_part_header(part, rec->uid, section, sect, data);

	return FALSE;
}

void index_fetch_body_section(MailIndexRecord *rec,
			      unsigned int seq __attr_unused__,
			      MailFetchBodyData *sect, FetchData *data)
{
	const char *str;
	int fetch_ok;

	str = !sect->skip_set ?
		t_strdup_printf(" BODY[%s] ", sect->section) :
		t_strdup_printf(" BODY[%s]<%lu> ", sect->section,
				(unsigned long) sect->skip);
	(void)io_buffer_send(data->outbuf, str, strlen(str));

	if (*sect->section == '\0') {
		fetch_ok = fetch_body(rec, sect, data, TRUE);
	} else if (strcasecmp(sect->section, "TEXT") == 0) {
		fetch_ok = fetch_body(rec, sect, data, FALSE);
	} else if (strncasecmp(sect->section, "HEADER", 6) == 0) {
		fetch_ok = fetch_header(rec, sect, data);
	} else if (*sect->section >= '0' && *sect->section <= '9') {
		fetch_ok = fetch_part(rec, sect, data);
	} else {
		fetch_ok = FALSE;
	}

	if (!fetch_ok) {
		/* error */
		(void)io_buffer_send(data->outbuf, "{0}\r\n", 5);
	}
}

/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "ioloop.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>

static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static MailIndexRecord *
mail_index_record_append(MailIndex *index, time_t internal_date,
			 size_t full_virtual_size)
{
	MailIndexRecord trec, *rec;

	memset(&trec, 0, sizeof(MailIndexRecord));
	trec.internal_date = internal_date;
	trec.full_virtual_size = full_virtual_size;

	rec = &trec;
	if (!index->append(index, &rec))
		return NULL;

	return rec;
}

static time_t from_line_parse_date(const char *msg, size_t size)
{
	const char *msg_end;
	struct tm tm;
	int i;

	/* From <sender> <date> <moreinfo> */
	if (strncmp(msg, "From ", 5) != 0)
		return 0;

	msg_end = msg + size;

	/* skip sender */
	msg += 5;
	while (*msg != ' ' && msg < msg_end) msg++;
	while (*msg == ' ' && msg < msg_end) msg++;

	/* next 24 chars are the date in asctime() format,
	   eg. "Thu Nov 29 22:33:52 2001" */
	if (msg+24 > msg_end)
		return 0;

	memset(&tm, 0, sizeof(tm));

	/* skip weekday */
	msg += 4;

	/* month */
	for (i = 0; i < 12; i++) {
		if (strncasecmp(months[i], msg, 3) == 0) {
			tm.tm_mon = i;
			break;
		}
	}

	if (i == 12 || msg[3] != ' ')
		return 0;
	msg += 4;

	/* day */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ' ')
		return 0;
	tm.tm_mday = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* hour */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ':')
		return 0;
	tm.tm_hour = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* minute */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ':')
		return 0;
	tm.tm_min = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* second */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ' ')
		return 0;
	tm.tm_sec = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* year */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) ||
	    !i_isdigit(msg[2]) || !i_isdigit(msg[3]))
		return 0;
	tm.tm_year = (msg[0]-'0') * 1000 + (msg[1]-'0') * 100 +
		(msg[2]-'0') * 10 + (msg[3]-'0') - 1900;

	tm.tm_isdst = -1;
	return mktime(&tm);
}

static void header_func(MessagePart *part __attr_unused__,
			const char *name, unsigned int name_len,
			const char *value, unsigned int value_len,
			void *user_data)
{
	MailIndexRecord *rec = user_data;

	rec->msg_flags |= mbox_header_get_flags(name, name_len,
						value, value_len);
}

static int mbox_index_append_data(MailIndex *index, const char *msg,
				  off_t offset, size_t physical_size,
				  size_t virtual_size)
{
	MailIndexRecord *rec;
	MailIndexUpdate *update;
	time_t internal_date;
	char location[MAX_INT_STRLEN];
	unsigned int i;

	internal_date = from_line_parse_date(msg, physical_size);
	if (internal_date <= 0)
		internal_date = ioloop_time;

	/* skip the From-line */
	for (i = 0; i < physical_size; i++) {
		if (msg[i] == '\n') {
			i++;
			break;
		}
	}

	if (i == physical_size)
		return FALSE;

	msg += i;
	offset += i;
	physical_size -= i;
	virtual_size -= i;
	if (i > 0 && msg[i-1] != '\r')
		virtual_size--;

	rec = mail_index_record_append(index, internal_date, virtual_size);
	if (rec == NULL)
		return FALSE;

	update = index->update_begin(index, rec);

	/* location = offset to beginning of message */
	i_snprintf(location, sizeof(location), "%lu", (unsigned long) offset);
	index->update_field(update, FIELD_TYPE_LOCATION, location, 0);

	/* parse the header and add cache wanted fields */
	mail_index_update_headers(update, msg, physical_size, header_func, rec);

	if (!index->update_end(update)) {
		/* failed - delete the record */
		(void)index->expunge(index, rec, 0, FALSE);
		return FALSE;
	}

	return TRUE;
}

int mbox_index_append_mmaped(MailIndex *index, const char *data,
			     size_t data_size, off_t start_offset)
{
	const char *data_start, *data_end, *start, *cr;
	size_t size, vsize;
	off_t pos;
	int missing_cr_count;

	/* we should start with "From ". if we don't, something's messed up
	   and we should check the whole file instead. */
	if (strncmp(data, "From ", 5) != 0) {
		index->set_flags |= MAIL_INDEX_FLAG_FSCK;
		return FALSE;
	}

	/* each message ends at "\nFrom ". first get the size of the message,
	   then parse it. calculate the missing CR count as well. */
	start = data; cr = NULL; missing_cr_count = 0;

	data_start = data;
	data_end = data + data_size;
	for (; data != data_end; data++) {
		if (*data == '\r')
			cr = data;
		else if (*data == '\n') {
			if (cr != data-1)
				missing_cr_count++;

			if (data+6 < data_end && data[1] == 'F' &&
			    data[2] == 'r' && data[3] == 'o' &&
			    data[4] == 'm' && data[5] == ' ') {
				/* end of message */
				pos = (off_t) (start - data_start) +
					start_offset;
				size = (size_t) (data - start) + 1;
				vsize = size + missing_cr_count;
				if (!mbox_index_append_data(index, start, pos,
							    size, vsize))
					return FALSE;

				missing_cr_count = 0;
				start = data+1;
			}
		}
	}

	/* last message */
	pos = (off_t) (start - data_start);
	size = (size_t) (data - start);
	vsize = size + missing_cr_count;
	return mbox_index_append_data(index, start, pos, size, vsize);
}

int mbox_index_append(MailIndex *index, int fd, const char *path)
{
	void *mmap_base;
	size_t mmap_length;
	off_t pos, end_pos;
	int ret;

	/* get our current position */
	pos = lseek(fd, 0, SEEK_CUR);

	/* get the size of the file */
	end_pos = lseek(fd, 0, SEEK_END);

	if (pos == (off_t)-1 || end_pos == (off_t)-1) {
		index_set_error(index, "lseek() failed with mbox file %s: %m",
				path);
		return FALSE;
	}

	if (pos == end_pos) {
		/* no new data */
		return TRUE;
	}

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* mmap() the file */
	mmap_length = end_pos-pos;
	mmap_base = mmap(NULL, mmap_length, PROT_READ, MAP_SHARED, fd, pos);
	if (mmap_base == MAP_FAILED) {
		index_set_error(index, "mmap() failed with mbox file %s: %m",
				path);
		return FALSE;
	}

	(void)madvise(mmap_base, mmap_length, MADV_SEQUENTIAL);

	ret = mbox_index_append_mmaped(index, mmap_base, mmap_length, pos);
	(void)munmap(mmap_base, mmap_length);
	return ret;
}

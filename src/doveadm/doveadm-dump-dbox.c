/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-dec.h"
#include "istream.h"
#include "index/dbox-common/dbox-file.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static void
dump_timestamp(struct istream *input, const char *name, const char *value)
{
	time_t t;

	if (strcmp(value, "0") == 0)
		t = 0;
	else {
		t = hex2dec((const void *)value, strlen(value));
		if (t == 0) {
			i_fatal("Invalid %s at %"PRIuUOFF_T": %s",
				name, input->v_offset, value);
		}
	}
	printf("%s = %ld (%s)\n", name, (long)t, unixdate2str(t));
}

static uoff_t
dump_size(struct istream *input, const char *name, const char *value)
{
	uoff_t size;

	if (strcmp(value, "0") == 0)
		size = 0;
	else {
		size = hex2dec((const void *)value, strlen(value));
		if (size == 0) {
			i_fatal("Invalid %s at %"PRIuUOFF_T": %s",
				name, input->v_offset, value);
		}
	}
	printf("%s = %"PRIuUOFF_T"\n", name, size);
	return size;
}

static unsigned int dump_file_hdr(struct istream *input)
{
	const char *line, *const *arg, *version;
	unsigned int msg_hdr_size = 0;

	if ((line = i_stream_read_next_line(input)) == NULL)
		i_fatal("Empty file");
	arg = t_strsplit(line, " ");

	/* check version */
	version = *arg;
	if (version == NULL || !str_is_numeric(version, ' '))
		i_fatal("%s is not a dbox file", i_stream_get_name(input));
	if (strcmp(version, "2") != 0)
		i_fatal("Unsupported dbox file version %s", version);
	arg++;

	for (; *arg != NULL; arg++) {
		switch (**arg) {
		case DBOX_HEADER_MSG_HEADER_SIZE:
			msg_hdr_size = hex2dec((const void *)(*arg + 1),
					       strlen(*arg + 1));
			if (msg_hdr_size == 0) {
				i_fatal("Invalid msg_header_size header: %s",
					*arg + 1);
			}
			printf("file.msg_header_size = %u\n", msg_hdr_size);
			break;
		case DBOX_HEADER_CREATE_STAMP:
			dump_timestamp(input, "file.create_stamp", *arg + 1);
			break;
		default:
			printf("file.unknown-%c = %s\n", **arg, *arg + 1);
			break;
		}
	}
	if (msg_hdr_size == 0)
		i_fatal("Missing msg_header_size in file header");
	return msg_hdr_size;
}

static bool
dump_msg_hdr(struct istream *input, unsigned int hdr_size, uoff_t *msg_size_r)
{
	struct dbox_message_header hdr;
	const unsigned char *data;
	size_t size;
	uoff_t msg_size;

	if (i_stream_read_bytes(input, &data, &size, hdr_size) <= 0) {
		if (size == 0)
			return FALSE;
		i_fatal("Partial message header read at %"PRIuUOFF_T": "
			"%"PRIuSIZE_T" bytes", input->v_offset, size);
	}
	printf("offset %"PRIuUOFF_T":\n", input->v_offset);

	if (hdr_size < sizeof(hdr))
		i_fatal("file.hdr_size too small: %u", hdr_size);
	memcpy(&hdr, data, sizeof(hdr));

	if (memcmp(hdr.magic_pre, DBOX_MAGIC_PRE, sizeof(hdr.magic_pre)) != 0)
		i_fatal("dbox wrong pre-magic at %"PRIuUOFF_T, input->v_offset);

	msg_size = dump_size(input, "msg.size",
		t_strndup(hdr.message_size_hex, sizeof(hdr.message_size_hex)));

	i_stream_skip(input, hdr_size);
	*msg_size_r = msg_size;
	return TRUE;
}

static void dump_msg_metadata(struct istream *input)
{
	struct dbox_metadata_header hdr;
	const unsigned char *data;
	size_t size;
	const char *line;

	/* verify magic */
	if (i_stream_read_bytes(input, &data, &size, sizeof(hdr)) <= 0) {
		i_fatal("dbox missing metadata at %"PRIuUOFF_T,
			input->v_offset);
	}
	memcpy(&hdr, data, sizeof(hdr));
	if (memcmp(hdr.magic_post, DBOX_MAGIC_POST, sizeof(hdr.magic_post)) != 0)
		i_fatal("dbox wrong post-magic at %"PRIuUOFF_T, input->v_offset);
	i_stream_skip(input, sizeof(hdr));

	/* dump the metadata */
	for (;;) {
		if ((line = i_stream_read_next_line(input)) == NULL)
			i_fatal("dbox metadata ended unexpectedly at EOF");
		if (*line == '\0')
			break;

		switch (*line) {
		case DBOX_METADATA_GUID:
			printf("msg.guid = %s\n", line + 1);
			break;
		case DBOX_METADATA_POP3_UIDL:
			printf("msg.pop3-uidl = %s\n", line + 1);
			break;
		case DBOX_METADATA_POP3_ORDER:
			printf("msg.pop3-order = %s\n", line + 1);
			break;
		case DBOX_METADATA_RECEIVED_TIME:
			dump_timestamp(input, "msg.received", line + 1);
			break;
		case DBOX_METADATA_PHYSICAL_SIZE:
			(void)dump_size(input, "msg.physical-size", line + 1);
			break;
		case DBOX_METADATA_VIRTUAL_SIZE:
			(void)dump_size(input, "msg.virtual-size", line + 1);
			break;
		case DBOX_METADATA_EXT_REF:
			printf("msg.ext-ref = %s\n", line + 1);
			break;
		case DBOX_METADATA_ORIG_MAILBOX:
			printf("msg.orig-mailbox = %s\n", line + 1);
			break;

		case DBOX_METADATA_OLDV1_EXPUNGED:
		case DBOX_METADATA_OLDV1_FLAGS:
		case DBOX_METADATA_OLDV1_KEYWORDS:
		case DBOX_METADATA_OLDV1_SAVE_TIME:
		case DBOX_METADATA_OLDV1_SPACE:
			printf("msg.obsolete-%c = %s\n", *line, line + 1);
			break;
		}
	}
}

static bool dump_msg(struct istream *input, unsigned int hdr_size)
{
	uoff_t msg_size;

	if (!dump_msg_hdr(input, hdr_size, &msg_size))
		return FALSE;
	i_stream_skip(input, msg_size);
	dump_msg_metadata(input);
	return TRUE;
}

static void cmd_dump_dbox(int argc ATTR_UNUSED, char *argv[])
{
	struct istream *input;
	int fd;
	unsigned int hdr_size;
	bool ret;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", argv[1]);

	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
	i_stream_set_name(input, argv[1]);
	hdr_size = dump_file_hdr(input);
	do {
		printf("\n");
		T_BEGIN {
			ret = dump_msg(input, hdr_size);
		} T_END;
	} while (ret);
	i_stream_destroy(&input);
}

static bool test_dump_dbox(const char *path)
{
	const char *p;

	p = strrchr(path, '/');
	if (p == NULL)
		p = path;
	else
		p++;
	return str_begins(p, "m.") || str_begins(p, "u.");
}

struct doveadm_cmd_dump doveadm_cmd_dump_dbox = {
	"dbox",
	test_dump_dbox,
	cmd_dump_dbox
};

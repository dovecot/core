/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-parser.h"
#include "fts-parser.h"

#include <unistd.h>

int main(void)
{
	struct fts_parser *parser;
	unsigned char buf[IO_BLOCK_SIZE];
	struct message_block block;
	ssize_t ret;

	lib_init();

	parser = fts_parser_html.try_init(NULL, "text/html", NULL);
	i_assert(parser != NULL);

	memset(&block, 0, sizeof(block));
	while ((ret = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
		block.data = buf;
		block.size = ret;
		parser->v.more(parser, &block);
		write(STDOUT_FILENO, block.data, block.size);
	}

	for (;;) {
		block.size = 0;
		parser->v.more(parser, &block);
		if (block.size == 0)
			break;
		write(STDOUT_FILENO, block.data, block.size);
	}

	lib_deinit();
}

/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service.h"
#include "config-parser-private.h"
#include "old-set-parser.h"

static void ATTR_FORMAT(2, 3)
obsolete(struct config_parser_context *ctx, const char *str, ...)
{
	static bool seen_obsoletes = FALSE;
	va_list args;

	if (ctx->hide_obsolete_warnings)
		return;

	if (!seen_obsoletes) {
		i_warning("NOTE: You can get a new clean config file with: "
			  "doveconf -Pn > dovecot-new.conf");
		seen_obsoletes = TRUE;
	}

	va_start(args, str);
	i_warning("Obsolete setting in %s:%u: %s",
		  ctx->cur_input->path, ctx->cur_input->linenum,
		  t_strdup_vprintf(str, args));
	va_end(args);
}

bool old_settings_handle(struct config_parser_context *ctx ATTR_UNUSED,
			 const struct config_line *line)
{
	switch (line->type) {
	case CONFIG_LINE_TYPE_SKIP:
	case CONFIG_LINE_TYPE_CONTINUE:
	case CONFIG_LINE_TYPE_ERROR:
	case CONFIG_LINE_TYPE_INCLUDE:
	case CONFIG_LINE_TYPE_INCLUDE_TRY:
	case CONFIG_LINE_TYPE_SECTION_BEGIN:
	case CONFIG_LINE_TYPE_SECTION_END:
	case CONFIG_LINE_TYPE_GROUP_SECTION_BEGIN:
		break;
	case CONFIG_LINE_TYPE_KEYFILE:
	case CONFIG_LINE_TYPE_KEYVALUE:
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		break;
	}
	return FALSE;
}

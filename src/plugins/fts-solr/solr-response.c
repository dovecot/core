/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "solr-response.h"

#include <expat.h>

enum solr_xml_response_state {
	SOLR_XML_RESPONSE_STATE_ROOT,
	SOLR_XML_RESPONSE_STATE_RESPONSE,
	SOLR_XML_RESPONSE_STATE_RESULT,
	SOLR_XML_RESPONSE_STATE_DOC,
	SOLR_XML_RESPONSE_STATE_CONTENT
};

enum solr_xml_content_state {
	SOLR_XML_CONTENT_STATE_NONE = 0,
	SOLR_XML_CONTENT_STATE_UID,
	SOLR_XML_CONTENT_STATE_SCORE,
	SOLR_XML_CONTENT_STATE_MAILBOX,
	SOLR_XML_CONTENT_STATE_NAMESPACE,
	SOLR_XML_CONTENT_STATE_UIDVALIDITY,
	SOLR_XML_CONTENT_STATE_ERROR
};

struct solr_lookup_xml_context {
	enum solr_xml_response_state state;
	enum solr_xml_content_state content_state;
	int depth;

	uint32_t uid, uidvalidity;
	float score;
	char *mailbox, *ns;

	pool_t result_pool;
	/* box_id -> solr_result */
	HASH_TABLE(char *, struct solr_result *) mailboxes;
	ARRAY(struct solr_result *) results;
};

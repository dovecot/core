#ifndef DICT_CLIENT_H
#define DICT_CLIENT_H

#include "dict.h"

#define DEFAULT_DICT_SERVER_SOCKET_FNAME "dict"

#define DICT_CLIENT_PROTOCOL_MAJOR_VERSION 2
#define DICT_CLIENT_PROTOCOL_MINOR_VERSION 0

#define DICT_CLIENT_MAX_LINE_LENGTH (64*1024)

enum {
        /* <major-version> <minor-version> <value type> <user> <dict name> */
	DICT_PROTOCOL_CMD_HELLO = 'H',

	DICT_PROTOCOL_CMD_LOOKUP = 'L', /* <key> */
	DICT_PROTOCOL_CMD_ITERATE = 'I', /* <flags> <path> */

	DICT_PROTOCOL_CMD_BEGIN = 'B', /* <id> */
	DICT_PROTOCOL_CMD_COMMIT = 'C', /* <id> */
	DICT_PROTOCOL_CMD_COMMIT_ASYNC = 'D', /* <id> */
	DICT_PROTOCOL_CMD_ROLLBACK = 'R', /* <id> */

	DICT_PROTOCOL_CMD_SET = 'S', /* <id> <key> <value> */
	DICT_PROTOCOL_CMD_UNSET = 'U', /* <id> <key> */
	DICT_PROTOCOL_CMD_ATOMIC_INC = 'A' /* <id> <key> <diff> */
};

enum {
	DICT_PROTOCOL_REPLY_OK = 'O', /* <value> */
	DICT_PROTOCOL_REPLY_NOTFOUND = 'N',
	DICT_PROTOCOL_REPLY_FAIL = 'F',
	DICT_PROTOCOL_REPLY_ASYNC_COMMIT = 'A'
};

const char *dict_client_escape(const char *src);
const char *dict_client_unescape(const char *src);

#endif

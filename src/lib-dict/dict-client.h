#ifndef DICT_CLIENT_H
#define DICT_CLIENT_H

#include "dict.h"

#define DEFAULT_DICT_SERVER_SOCKET_FNAME "dict"

#define DICT_CLIENT_PROTOCOL_MAJOR_VERSION 2
#define DICT_CLIENT_PROTOCOL_MINOR_VERSION 2

#define DICT_CLIENT_PROTOCOL_VERSION_MIN_MULTI_OK 2

#define DICT_CLIENT_MAX_LINE_LENGTH (64*1024)

enum dict_protocol_cmd {
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
	DICT_PROTOCOL_CMD_ATOMIC_INC = 'A', /* <id> <key> <diff> */
	DICT_PROTOCOL_CMD_TIMESTAMP = 'T', /* <id> <secs> <nsecs> */
};

enum dict_protocol_reply {
	DICT_PROTOCOL_REPLY_ERROR = -1,

	DICT_PROTOCOL_REPLY_OK = 'O', /* <value> */
	DICT_PROTOCOL_REPLY_MULTI_OK = 'M', /* protocol v2.2+ */
	DICT_PROTOCOL_REPLY_NOTFOUND = 'N',
	DICT_PROTOCOL_REPLY_FAIL = 'F',
	DICT_PROTOCOL_REPLY_WRITE_UNCERTAIN = 'W',
	DICT_PROTOCOL_REPLY_ASYNC_COMMIT = 'A',
	DICT_PROTOCOL_REPLY_ITER_FINISHED = '\0',
	DICT_PROTOCOL_REPLY_ASYNC_ID = '*',
	DICT_PROTOCOL_REPLY_ASYNC_REPLY = '+',
};

#endif

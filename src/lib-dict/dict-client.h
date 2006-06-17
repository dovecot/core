#ifndef __DICT_CLIENT_H
#define __DICT_CLIENT_H

#define DEFAULT_DICT_SERVER_SOCKET_PATH PKG_RUNDIR"/dict-server"

#define DICT_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define DICT_CLIENT_PROTOCOL_MINOR_VERSION 0

#define DICT_CLIENT_MAX_LINE_LENGTH (64*1024)

enum {
        /* <major-version> <minor-version> <user> <dict name> */
	DICT_PROTOCOL_CMD_HELLO = 'H',

	DICT_PROTOCOL_CMD_LOOKUP = 'L', /* <key> */
	DICT_PROTOCOL_CMD_ITERATE = 'I', /* <recurse> <path> */

	DICT_PROTOCOL_CMD_BEGIN = 'B', /* <id> */
	DICT_PROTOCOL_CMD_COMMIT = 'C', /* <id> */
	DICT_PROTOCOL_CMD_ROLLBACK = 'R', /* <id> */

	DICT_PROTOCOL_CMD_SET = 'S', /* <id> <key> <value> */
	DICT_PROTOCOL_CMD_ATOMIC_INC = 'A' /* <id> <key> <diff> */
};

enum {
	/* For LOOKUP command */
	DICT_PROTOCOL_REPLY_OK = 'O', /* <value> */
	DICT_PROTOCOL_REPLY_NOTFOUND = 'N',
	DICT_PROTOCOL_REPLY_FAIL = 'F'
};

const char *dict_client_escape(const char *src);
const char *dict_client_unescape(const char *src);

void dict_client_register(void);
void dict_client_unregister(void);

#endif

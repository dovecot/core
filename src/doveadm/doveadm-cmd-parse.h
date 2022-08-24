#ifndef DOVEADM_CMD_PARSE_H
#define DOVEADM_CMD_PARSE_H

#include "net.h"

#define DOVEADM_CMD_PARAMS_START .parameters = (const struct doveadm_cmd_param[]){
#define DOVEADM_CMD_PARAM(optP, nameP, typeP, flagP) DOVEADM_CMD_PARAMKV(optP, nameP, nameP, typeP, flagP)
#define DOVEADM_CMD_PARAMKV(optP, nameP, keyP, typeP, flagP) { .short_opt = optP, .name = nameP, .key = keyP, .type = typeP, .flags = flagP },
#define DOVEADM_CMD_PARAMS_END { .short_opt = '\0', .name = NULL, .type = CMD_PARAM_BOOL, .flags = CMD_PARAM_FLAG_NONE } }

struct doveadm_cmd_context;
struct doveadm_mail_cmd_context;

typedef enum {
	CMD_PARAM_BOOL = 0, /* value in v_bool */
	CMD_PARAM_INT64,    /* value in v_int64 */
	CMD_PARAM_IP,	    /* value in v_ip (struct ip_addr) */
	CMD_PARAM_STR,      /* value in v_string (const char*) */
	CMD_PARAM_ARRAY,    /* value in v_array (const char*[]) */
	CMD_PARAM_ISTREAM   /* value in v_istream (struct istream*) */
} doveadm_cmd_param_t;

typedef enum {
	CMD_PARAM_FLAG_NONE		= 0x0,

	/* Meaningful only while parsing a command line command */
	CMD_PARAM_FLAG_POSITIONAL 	= 0x1,

	CMD_PARAM_FLAG_DO_NOT_EXPOSE	= 0x2,

	/* Grant that the parsed int64 is non negative */
	CMD_PARAM_FLAG_UNSIGNED		= 0x4,

	/* While parsing a command line command,
	   if the current argument matches the parameter key, the following
	   argument is consumed as its value. Multiple consecutive key_value
	   parameters are all evaluated independent of their ordering against
	   the current argument.

	   The parameter key is by default the same as the parameter name,
	   unless DOVEADM_CMD_PARAMKV is used to specify a distinct key.

	   If the current argument doesn't match any key_value parameter for
	   the current position, the next plain positional argument will be
	   filled (if any).

	   See test-doveadm-cmd-parse.c for more details.
	  */
	CMD_PARAM_FLAG_KEY_VALUE	= 0x8,
} doveadm_cmd_param_flag_t;

typedef enum {
	CMD_FLAG_NONE			= 0x0,
	CMD_FLAG_HIDDEN			= 0x1,
	CMD_FLAG_NO_PRINT		= 0x2,
	/* Don't parse any -options for the command. */
	CMD_FLAG_NO_OPTIONS		= 0x4,
	/* Prevent GNU getopt() from finding options after the first
	   non-option is seen (e.g. "-1 arg -2" would parse -1 but not -2
	   as option). */
	CMD_FLAG_NO_UNORDERED_OPTIONS	= 0x8,
} doveadm_cmd_flag_t;

struct doveadm_cmd_param {
	char short_opt;
	const char *name;
	const char *key;
	doveadm_cmd_param_t type;
	bool value_set;
	struct {
		bool v_bool;
		int64_t v_int64;
		const char* v_string;
		ARRAY_TYPE(const_string) v_array;
		struct ip_addr v_ip;
		struct istream* v_istream;
	} value;
	doveadm_cmd_param_flag_t flags;
};
ARRAY_DEFINE_TYPE(doveadm_cmd_param_arr_t, struct doveadm_cmd_param);

typedef void doveadm_command_ver2_t(struct doveadm_cmd_context *cctx);

struct doveadm_cmd_ver2 {
	doveadm_command_ver2_t *cmd;
	struct doveadm_mail_cmd_context *(*mail_cmd)(void);
	const char *name;
	const char *usage;
	doveadm_cmd_flag_t flags;
	const struct doveadm_cmd_param *parameters;
};

struct doveadm_cmd_context {
	const struct doveadm_cmd_ver2 *cmd; /* for help */

	pool_t pool;
	int argc;
	const struct doveadm_cmd_param *argv;

	const char *username;
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;
	/* extra fields (e.g. forward_*) sent via doveadm protocol */
	const char *const *extra_fields;

	enum doveadm_client_type conn_type;
	struct istream *input;
	struct ostream *output;
	struct event *event;

	/* non-NULL if doveadm-server should return referral to another
	   server instead. */
	const char *referral;
	bool proxy_redirect_reauth;
};

struct doveadm_cmd_context*
doveadm_cmd_context_create(enum doveadm_client_type conn_type, bool forced_debug);
void doveadm_cmd_context_unref(struct doveadm_cmd_context **cctx);

/* Returns 0 if success, -1 if parameters were invalid. */
int doveadm_cmdline_run(int argc, const char *const argv[],
			struct doveadm_cmd_context *cctx);

bool doveadm_cmd_param_bool(const struct doveadm_cmd_context *cctx,
			    const char *name, bool *value_r);

static inline bool
doveadm_cmd_param_flag(const struct doveadm_cmd_context *cctx, const char *name)
{
	bool ignore ATTR_UNUSED;
	return doveadm_cmd_param_bool(cctx, name, &ignore);
}

bool doveadm_cmd_param_int64(const struct doveadm_cmd_context *cctx,
			     const char *name, int64_t *value_r);
bool doveadm_cmd_param_uint64(const struct doveadm_cmd_context *cctx,
			      const char *name, uint64_t *value_r);
bool doveadm_cmd_param_int32(const struct doveadm_cmd_context *cctx,
			     const char *name, int32_t *value_r);
bool doveadm_cmd_param_uint32(const struct doveadm_cmd_context *cctx,
			      const char *name, uint32_t *value_r);
bool doveadm_cmd_param_str(const struct doveadm_cmd_context *cctx,
			   const char *name, const char **value_r);
bool doveadm_cmd_param_ip(const struct doveadm_cmd_context *cctx,
			  const char *name, struct ip_addr *value_r);

bool doveadm_cmd_param_array_get(const struct doveadm_cmd_context *cctx,
				 const char *name,
				 ARRAY_TYPE(const_string) *value_r);
bool doveadm_cmd_param_array_append(const struct doveadm_cmd_context *cctx,
				    const char *name,
				    ARRAY_TYPE(const_string) *dest);
bool doveadm_cmd_param_array(const struct doveadm_cmd_context *cctx,
			     const char *name, const char *const **value_r);

bool doveadm_cmd_param_istream(const struct doveadm_cmd_context *cctx,
			       const char *name, struct istream **value_r);

void doveadm_cmd_params_clean(ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv);
void doveadm_cmd_params_null_terminate_arrays(ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv);

/* debug functions */
void doveadm_cmd_args_dump(const char *const *items);
void doveadm_cmd_params_dump(const struct doveadm_cmd_context *cctx);

#endif

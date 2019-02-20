#ifndef DOVEADM_PRINT_H
#define DOVEADM_PRINT_H

#define DOVEADM_PRINT_TYPE_TAB "tab"
#define DOVEADM_PRINT_TYPE_FLOW "flow"
#define DOVEADM_PRINT_TYPE_PAGER "pager"
#define DOVEADM_PRINT_TYPE_TABLE "table"
#define DOVEADM_PRINT_TYPE_SERVER "server"
#define DOVEADM_PRINT_TYPE_JSON "json"
#define DOVEADM_PRINT_TYPE_FORMATTED "formatted"

enum doveadm_print_header_flags {
	DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY 	= 0x01,
	DOVEADM_PRINT_HEADER_FLAG_STICKY	 	= 0x02,
	DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE	 	= 0x04,
	DOVEADM_PRINT_HEADER_FLAG_EXPAND	 	= 0x08,
	DOVEADM_PRINT_HEADER_FLAG_NUMBER		= 0x10
};

extern const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[];
extern bool doveadm_print_hide_titles;
/* points to either stdout or to doveadm-server's TCP connection */
extern struct ostream *doveadm_print_ostream;

bool doveadm_print_is_initialized(void);

void doveadm_print_header(const char *key, const char *title,
			  enum doveadm_print_header_flags flags);
void doveadm_print_header_simple(const char *key_title);
unsigned int doveadm_print_get_headers_count(void);

void doveadm_print(const char *value);
void doveadm_print_num(uintmax_t value);
/* Stream for same field continues until len=0 */
void doveadm_print_stream(const void *value, size_t size);
/* Print the whole input stream. Returns 0 if ok, -1 if stream read() failed */
int doveadm_print_istream(struct istream *input);
void doveadm_print_sticky(const char *key, const char *value);
void doveadm_print_flush(void);
void doveadm_print_unstick_headers(void);

void doveadm_print_init(const char *name);
void doveadm_print_deinit(void);

void doveadm_print_formatted_set_format(const char *format);

#endif

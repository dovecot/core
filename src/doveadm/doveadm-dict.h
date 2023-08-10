#ifndef DOVEADM_DICT_H
#define DOVEADM_DICT_H

void doveadm_dict_get(struct doveadm_cmd_context *cctx, const char *key);
void doveadm_dict_set(struct doveadm_cmd_context *cctx, const char *key,
		      const char *value);
void doveadm_dict_unset(struct doveadm_cmd_context *cctx, const char *key);
void doveadm_dict_inc(struct doveadm_cmd_context *cctx, const char *key,
		      int64_t diff);
void doveadm_dict_iter(struct doveadm_cmd_context *cctx,
		       enum dict_iterate_flags iter_flags, const char *prefix);

#endif

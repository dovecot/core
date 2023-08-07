#ifndef DOVEADM_FS_H
#define DOVEADM_FS_H

void doveadm_fs_get(struct doveadm_cmd_context *cctx, const char *path);
void doveadm_fs_put(struct doveadm_cmd_context *cctx,
		    const char *src_path, const char *dest_path,
		    const buffer_t *hash);
void doveadm_fs_copy(struct doveadm_cmd_context *cctx,
		     const char *src_path, const char *dest_path);
void doveadm_fs_stat(struct doveadm_cmd_context *cctx, const char *path);
void doveadm_fs_metadata(struct doveadm_cmd_context *cctx, const char *path);
void doveadm_fs_delete_recursive(struct doveadm_cmd_context *cctx,
				 const char *const *paths,
				 unsigned int async_count);
void doveadm_fs_delete_paths(struct doveadm_cmd_context *cctx,
			     const char *const *paths,
			     unsigned int async_count);
void doveadm_fs_iter(struct doveadm_cmd_context *cctx,
		     enum fs_iter_flags flags, const char *path);

#endif

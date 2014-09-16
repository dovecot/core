#ifndef DOVEADM_DSYNC_H
#define DOVEADM_DSYNC_H

extern struct doveadm_mail_cmd cmd_dsync_mirror;
extern struct doveadm_mail_cmd cmd_dsync_backup;
extern struct doveadm_mail_cmd cmd_dsync_server;

void doveadm_dsync_main(int *_argc, char **_argv[]);

#endif

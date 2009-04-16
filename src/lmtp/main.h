#ifndef MAIN_H
#define MAIN_H

extern struct master_service *service;
extern struct mail_storage_service_multi_ctx *multi_service;

void listener_client_destroyed(void);

#endif

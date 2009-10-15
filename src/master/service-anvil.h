#ifndef SERVICE_ANVIL_H
#define SERVICE_ANVIL_H

int service_list_init_anvil(struct service_list *service_list,
			    const char **error_r);
void service_list_deinit_anvil(struct service_list *service_list);
void services_anvil_init(struct service_list *service_list);

void service_anvil_process_created(struct service *service);
void service_anvil_process_destroyed(struct service *service);

#endif

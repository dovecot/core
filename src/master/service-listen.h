#ifndef SERVICE_LISTEN_H
#define SERVICE_LISTEN_H

/* Start listening in all services. Returns -1 for fatal failures,
   0 if some of the addresses are already being used or path for
   unix socket was lost, 1 if all is ok. It's safe to call this function
   multiple times. */
int services_listen(struct service_list *service_list);

/* Move common listener fds from old_services to new_services, close those
   that aren't needed anymore and finally call services_listen() to add
   missing listeners. */
int services_listen_using(struct service_list *new_service_list,
			  struct service_list *old_service_list);

#endif

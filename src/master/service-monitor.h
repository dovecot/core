#ifndef SERVICE_MONITOR_H
#define SERVICE_MONITOR_H

/* Start listening and monitoring services. */
void services_monitor_start(struct service_list *service_list);

/* Stop services. The stats service is left running - see
   services_monitor_stop_stats(). */
void services_monitor_stop(struct service_list *service_list, bool wait);
/* Tell the stats process to stop. Its writer clients reconnect as soon as it
   does, so the new generation's listeners have to exist already. */
void services_monitor_stop_stats(struct service_list *service_list);

/* Call after SIGCHLD has been detected */
void services_monitor_reap_children(void);

/* Stop monitoring the service. The stop pipe is closed only if
   close_stop_pipe is TRUE - see services_monitor_stop_stats(). */
void service_monitor_stop(struct service *service, bool close_stop_pipe);
/* Stop reading the service's status fd. The fd is also closed, except for the
   anvil service, whose status fd is globally shared with the next service
   list and closed only by service_anvil_global_deinit(). */
void service_monitor_close_status_fd(struct service *service);
void service_monitor_stop_close(struct service *service);
void service_monitor_listen_start(struct service *service);
void service_monitor_listen_stop(struct service *service);

#endif

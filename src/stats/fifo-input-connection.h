#ifndef FIFO_INPUT_CONNECTION_H
#define FIFO_INPUT_CONNECTION_H

struct fifo_input_connection *fifo_input_connection_create(int fd);
void fifo_input_connection_destroy(struct fifo_input_connection **conn);

void fifo_input_connections_destroy_all(void);

#endif

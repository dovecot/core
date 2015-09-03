#ifndef DICT_COMMANDS_H
#define DICT_COMMANDS_H

struct dict_connection;

int dict_command_input(struct dict_connection *conn, const char *line);

void dict_connection_cmds_output_more(struct dict_connection *conn);

#endif

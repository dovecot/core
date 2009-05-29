#ifndef DICT_COMMANDS_H
#define DICT_COMMANDS_H

struct dict_connection;

int dict_command_input(struct dict_connection *conn, const char *line);

#endif

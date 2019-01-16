@@
expression E;
@@

- if (E != NULL) {
- 	i_stream_unref(&E);
- }
+ i_stream_unref(&E);

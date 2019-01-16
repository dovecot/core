@@
expression e1, e2;
@@

- strncmp(e1, e2, strlen(e2)) == 0
+ str_begins(e1, e2)

@@
expression e1, e2;
@@

- strncmp(e1, e2, strlen(e2)) != 0
+ !str_begins(e1, e2)

@@
expression e1, e2;
@@

- strncmp(e1, e2, strlen(e1)) == 0
+ str_begins(e2, e1)

@@
expression e1, e2;
@@

- strncmp(e1, e2, strlen(e1)) != 0
+ !str_begins(e2, e1)

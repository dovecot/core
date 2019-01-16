@@
expression e1, e2;
identifier i2;
@@

  i2 = strlen(e2)
  ...
- strncmp(e1, e2, i2) == 0
+ str_begins(e1, e2)

@@
expression e1, e2;
identifier i2;
@@

  i2 = strlen(e2)
  ...
- strncmp(e1, e2, i2) != 0
+ !str_begins(e1, e2)

@@
expression e1, e2;
identifier i1;
@@

  i1 = strlen(e1)
  ...
- strncmp(e1, e2, i1) == 0
+ str_begins(e2, e1)

@@
expression e1, e2;
identifier i1;
@@

  i1 = strlen(e1)
  ...
- strncmp(e1, e2, i1) != 0
+ !str_begins(e2, e1)

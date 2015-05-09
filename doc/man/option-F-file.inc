.TP
.BI \-F\  file
Execute the
.I command
for all the users in the
.IR file .
This is similar to the
.B \-A
option,
but instead of getting the list of users from the userdb,
they are read from the given
.IR file .
The
.I file
contains one username per line.

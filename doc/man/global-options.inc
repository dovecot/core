.SH OPTIONS
Global
.BR doveadm (1)
.IR options :
.TP
.B \-D
Enables verbosity and debug messages.
.TP
.BI \-s\  socket_path
The option\(aqs argument is either an absolute path to a local UNIX domain
socket, or a hostname and port
.RI ( hostname : port ),
in order to connect a remote host via a TCP socket.
.sp
This allows an administrator to execute
.B doveadm mail
commands through the given socket.
.TP
.B \-v
Enables verbosity, including progress counter.

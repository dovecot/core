.TP
.BI \-S\  socket_path
The option\(aqs argument is either an absolute path to a local UNIX domain
socket, or a hostname and port
.RI ( hostname : port ),
in order to connect a remote host via a TCP socket.
.sp
This allows an administrator to execute
.BR doveadm (1)
mail commands through the given socket.

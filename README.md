gen_socket
===========

gen_socket is an Erlang socket interface which can be used to create
gen_tcp and gen_udp based sockets with special properties.

Existing use cases are:
  * gen_udp socket that talks netlink to the linux kernel
  * gen_tcp socket that is a unix domain socket

In all cases a special file descriptor is created and passed to the
gen_tcp/gen_udp driver for further handling

*WARNING*: pre R15, it was possible to create a non-INET socket and
	   have gen_udp work on it. With R15 the check rules in
	   fdopen() have been tightened to prevent this kind of
	   trickery.

COMPILING
---------
Try running: make



CFLAGS +=-Wall -Werror -fPIC -I. $(shell erl -noinput -eval 'io:format("-I~s -I~s/erts-~s/include", [code:lib_dir(erl_interface, include), code:root_dir(), erlang:system_info(version)]), halt(0).')
LDFLAGS +=$(shell erl -noinput -eval 'io:format("-L~s", [code:lib_dir(erl_interface, lib)]), halt(0).')

all: ../priv/lib/gen_socket_nif.so ../priv/lib/gen_socket.so

clean:
	rm -f ../priv/lib/*.so
	rm -f *.o

../priv/lib/gen_socket_nif.so: gen_socket_nif.o
	(test -d ../priv/lib || mkdir -p ../priv/lib)
	$(CC) $(CFLAGS) $(LDFLAGS) gen_socket_nif.o -o ../priv/lib/gen_socket_nif.so -shared -lei -lerl_interface

../priv/lib/gen_socket.so: gen_socket_drv.o
	(test -d ../priv/lib || mkdir -p ../priv/lib)
	$(CC) $(CFLAGS) $(LDFLAGS) gen_socket_drv.o -o ../priv/lib/gen_socket.so -shared -lei -lerl_interface

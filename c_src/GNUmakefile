
UNAME=$(shell uname)

ifeq ($(UNAME),Darwin)
	SHLIB_CFLAGS=-fPIC -bundle -flat_namespace -undefined suppress
else
	SHLIB_CFLAGS=-fPIC -shared
endif

CFLAGS +=-fPIC -I. $(shell erl -noinput -eval 'io:format("-I~s -I~s/erts-~s/include", [code:lib_dir(erl_interface, include), code:root_dir(), erlang:system_info(version)]), halt(0).')
LDFLAGS +=$(shell erl -noinput -eval 'io:format("-L~s", [code:lib_dir(erl_interface, lib)]), halt(0).')

all: ../priv/lib/gen_socket.so 

clean: 
	rm -f ../priv/lib/*.so
	rm -f *.o

../priv/lib/gen_socket.so: gen_socket.o
	(test -d ../priv/lib || mkdir -p ../priv/lib)
	$(CC) $(LDFLAGS) $(SHLIB_CFLAGS) -lei -lerl_interface gen_socket.o -o ../priv/lib/gen_socket.so

# Linux configuration
#
#AR = ar
#RANLIB = ranlib
#
#CFLAGS  = -DDEBUG -Wall -I../ip -O0
#LDFLAGS = -L../ip/ -lip -lcn

AR = aal
RANLIB = touch

CFLAGS  = -DDEBUG -Wall -I/usr/local/include/cn -I../ip -O0
LDFLAGS = -L../ip/ -L/usr/local/lib -lip -lcn
SOURCES = tcp.c
OBJECTS = tcp.o

all: libtcp.a

libtcp.a: $(OBJECTS)
	$(AR) rv libtcp.a $(OBJECTS)
	$(RANLIB) libtcp.a


clean:
	rm -f $(OBJECTS) libtcp.a a.out *.bak core errs



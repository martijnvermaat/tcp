# Linux configuration
#
#AR = ar
#RANLIB = ranlib
#
#CFLAGS  = -DDEBUG -Wall -I../tcp -I../ip -O0
#LDFLAGS = -L../ip -L../tcp -ltcp -lip -lcn
#
# Easiest thing to do is not to change this file every
# time when working on Linux, but to simply create a
# symbolic link from 'aal' to 'ar' (touch already exists)

AR = aal
RANLIB = touch

CFLAGS  = -DDEBUG -Wall -I/usr/local/include/cn -I../../../tcp -I../../../ip -O0
LDFLAGS = -L../../../ip -L../../../tcp -L/usr/local/lib -ltcp -lip -lcn

# why do we have to keep updating the Makefile when the test suite changes???
all: 01_compile.o 03_read_before_socket.o 04_write_before_socket.o 10_handshake.o 15_basic.o 18_write_one_byte.o 20_all_ascii.o
	$(CC) $(CFLAGS) -o ../build/01_compile 01_compile.o $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../build/03_read_before_socket 03_read_before_socket.o $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../build/04_write_before_socket 04_write_before_socket.o $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../build/10_handshake 10_handshake.o $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../build/15_basic 15_basic.o $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../build/18_write_one_byte 18_write_one_byte.o $(LDFLAGS)
	$(CC) $(CFLAGS) -o ../build/20_all_ascii 20_all_ascii.o $(LDFLAGS)
	rm -f *.o

clean:
	rm -f *.o a.out *.bak core errs
	rm -f ../build/*

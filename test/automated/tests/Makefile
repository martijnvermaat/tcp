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
all: 01_compile.o 03_rd_bf_soc.o 04_wr_bf_soc.o 10_handshake.o 15_basic.o 18_wr_1_byte.o 20_all_ascii.o 21_signl_lst.o 22_signal_rd.o 24_big_test.o 25_big_test.o 26_chops_rd.o
	$(CC) $(CFLAGS) -o ../build/26_chops_rd 26_chops_rd.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/25_big_test 25_big_test.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/24_big_test 24_big_test.o $(LDFLAGS)	
#	$(CC) $(CFLAGS) -o ../build/22_signal_rd 22_signal_rd.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/21_signl_lst 21_signl_lst.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/20_all_ascii 20_all_ascii.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/01_compile 01_compile.o $(LDFLAGS)    
#	$(CC) $(CFLAGS) -o ../build/03_rd_bf_soc 03_rd_bf_soc.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/04_wr_before_soc 04_wr_bf_soc.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/10_handshake 10_handshake.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/15_basic 15_basic.o $(LDFLAGS)
#	$(CC) $(CFLAGS) -o ../build/18_wr_1_byte 18_wr_1_byte.o $(LDFLAGS)

#	rm -f *.o

clean:
	rm -f *.o a.out *.bak core errs
	rm -f ../build/*

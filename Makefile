CC = gcc
LIBS = 
CFLAGS = -O2 -Wall
INSTALL = install -c
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin

all: clamdmon

clamdmon: clamdmon.c
	$(CC) $(CFLAGS) $(LIBS) -o clamdmon clamdmon.c
	strip clamdmon

clean:
	rm -f clamdmon

install:
	$(INSTALL) -m 755 clamdmon $(SBINDIR)
	$(INSTALL) -m 755 clamdmon.sh $(SBINDIR)

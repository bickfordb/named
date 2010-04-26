CC ?= gcc
CFLAGS += -std=c99
CFLAGS += $$(pkg-config --cflags --libs glib-2.0)
CFLAGS += $$(pkg-config --cflags --libs libevent)
CFLAGS += $$(pkg-config --cflags --libs sqlite3)

# Nested functions are disabled by default on Darwin
ifeq ($(shell uname), Darwin)
	CFLAGS += -fnested-functions
endif

all: bin/named

bin:
	install -d bin

bin/named: named.c list.c list.h dns.c dns.h bin
	$(CC) $(CFLAGS) -o $@ named.c list.c dns.c

clean-named:
	- rm -rf bin/named
	
clean: clean-named

test: bin/named test.db
	bin/named -d test.db

test.db: init.sql fixture.sql
	sqlite3 test.db <drop.sql
	sqlite3 test.db <init.sql
	sqlite3 test.db <fixture.sql

CC ?= gcc
CFLAGS += -std=c99
CFLAGS += $$(pkg-config --cflags --libs glib-2.0)
CFLAGS += $$(pkg-config --cflags --libs libevent)
CFLAGS += $$(pkg-config --cflags --libs sqlite3)
CFLAGS += -fnested-functions

all: bin/named

bin:
	install -d bin

bin/named: named.c bin
	$(CC) $(CFLAGS) -o $@ $<

clean-named:
	- rm -rf bin/named
	
clean: clean-named

test: bin/named test.db
	bin/named test.db

test.db: init.sql fixture.sql
	sqlite3 test.db <drop.sql
	sqlite3 test.db <init.sql
	sqlite3 test.db <fixture.sql

CC ?= gcc
C_FLAGS += -levent -lglib-2.0 -lsqlite3 -std=c99
C_FLAGS += -fnested-functions
LDFLAGS += -L/usr/local/lib 
LDFLAGS += -L/opt/local/lib

all: bin/named

clean:

bin/named: named.c
	install -d bin
	$(CC) $(C_FLAGS) $(LDFLAGS) -o $@ $+

clean-named:
	- rm -rf bin/named
	
clean: clean-named



test: bin/named test.db
	bin/named test.db

test.db: init.sql fixture.sql
	sqlite3 test.db <drop.sql
	sqlite3 test.db <init.sql
	sqlite3 test.db <fixture.sql

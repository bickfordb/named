all: bin/named

bin/named: src/NameDaemon.hs src/Main.hs
	ghc --make -o ./bin/named src/NameDaemon.hs src/Main.hs

clean:
	- rm -rf ./bin/named src/*.hi src/*.o

run: bin/named
	./bin/named --port=5138 --host=127.0.0.1

CC = gcc
SRC = Gee.External.Capstone.Proxy.c

Gee.External.Capstone.Proxy.so: Gee.External.Capstone.Proxy.o
	gcc -shared -o $@ Gee.External.Capstone.Proxy.o

Gee.External.Capstone.Proxy.o: Gee.External.Capstone.Proxy.c
	gcc -c -Wall -fPIC -o $@ $(SRC)

clean:
	rm -f *.so *.o

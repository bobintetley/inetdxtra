
all:	in.proxy

in.proxy:
	$(CC) $(CFLAGS) -o in.proxy in.proxy.c
	strip in.proxy
	cp in.proxy ../bin

clean:
	rm -f in.proxy

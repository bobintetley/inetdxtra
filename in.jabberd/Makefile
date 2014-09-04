
all:	in.jabberd

in.jabberd:
	$(CC) $(CFLAGS) -o in.jabberd in.jabberd.c sha1.c
	strip in.jabberd
	cp in.jabberd ../bin

clean:
	rm -f in.jabberd

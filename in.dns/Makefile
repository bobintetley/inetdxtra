
all:	in.dns

in.dns:
	$(CC) $(CFLAGS) -o in.dns in.dns.c
	strip in.dns
	cp in.dns ../bin

clean:
	rm -f in.dns

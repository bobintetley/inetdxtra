
all:	in.dhcp

in.dhcp: 
	$(CC) $(CFLAGS) -o in.dhcp in.dhcp.c
	strip in.dhcp
	cp in.dhcp ../bin

clean:
	rm -f in.dhcp

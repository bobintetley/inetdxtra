
all:	in.smtp

in.smtp:
	$(CC) $(CFLAGS) -o in.smtp in.smtp.c
	strip in.smtp
	cp in.smtp ../bin

clean:
	rm -f in.smtp

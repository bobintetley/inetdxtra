
VERSION=20140904
PREFIX=/usr/local/sbin
SUBDIR=in.dhcp in.dns in.mvp in.jabberd in.www in.proxy in.smtp in.ctcs

# Available CFLAGS:
# -DPACKETDUMP - force in.dns/in.dhcp to dump in/out packets to /tmp
#                for debugging
#
# -DLOGGING    - debug logging to the syslog for all apps
#  		 (daemon category)
#
# -DONELOG     - in.dhcp: log a single line for each response
#  		 in.www: output an NCSA combined logline in
#  		         /var/log/in.www.log for each request
#                in.proxy: output an NCSA combined logline in
#                        /var/log/in.proxy.log for each request
#  		 in.mvp: output a single line in the syslog
#                        for each response sent
#                in.jabberd: output login/logout events for users
#                in.smtp: log a line for each mail sent
#
#                (all daemons use daemon logging, except in.jabberd,
#                which uses auth for login/out events)
#
# -DCGI        - enable CGI support for in.www
#
# -DNORELATIVE - relative path protection for in.www
#
# -DUPDATEPS   - in.jabberd will update it's procname (for Linux only)
#                with the name of the logged in user
#                in.ctcs will also update to show the torrent file name
#
# -DUSE_NSS    - in.dns will use the NSS to resolve all queries instead
#                of its config file, making it behave as a recursive relay
#              - in.dhcp will use the NSS to discover IP addresses and
#                hostnames from MAC addresses of clients
#
export CFLAGS	:= -DONELOG -DNORELATIVE -DCGI -DUPDATEPS -Os -s

all:
	@mkdir -p bin
	@for i in $(SUBDIR); do cd $$i; if $(MAKE); then cd ..; else exit 1; fi; done;	
	@echo ""
	@echo "Now, run 'make install' as root."

clean:
	rm -rf bin
	@for i in $(SUBDIR); do cd $$i; if $(MAKE) clean; then cd ..; else exit 1; fi; done;	

install:
	cp -f bin/* $(PREFIX)
	@echo ""
	@echo "Make sure you update your inetd/xinetd.conf."

uninstall:
	for i in $(SUBDIR); do rm -rf $(PREFIX)/$$i; done

dist:	clean
	cd ..; tar --exclude .svn -czvf inetdxtra-$(VERSION)_src.tar.gz inetdxtra

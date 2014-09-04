#!/usr/bin/python

# Downloads a torrent file and starts up ctorrent with it

import cgi, sys, os, datetime

f = cgi.FieldStorage()
if not f:
	print "Location: download_new.html\n\n"
	sys.exit(0)

link = f["torrent"].value
now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
file = now + "." + link[link.rfind("/") + 1:]

# Download the torrent file
os.system("./ctorrentwget %s %s" % (file, link));

# Fire up the ctorrent instance
os.system("./ctorrentbg %s" % file)

# Redirect to the torrent watcher
print "Location: downloads.cgi\n\n"


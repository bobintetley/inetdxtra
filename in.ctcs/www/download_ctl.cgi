#!/usr/bin/python

# Issues a command by writing to /tmp/in.ctcs.pid.in
# "action" holds the action to send, pid holds the filename
import cgi, sys, os, datetime

f = cgi.FieldStorage()
if not f:
	print "Location: downloads.cgi\n\n"
	sys.exit(0)

action = f["action"].value
pid = f["pid"].value

# Open the pid file and write the command
p = open("/tmp/%s.in" % pid, "w")
p.write(action + "\n")
p.close();

# Redirect back to the torrent watcher
print "Location: downloads.cgi\n\n"


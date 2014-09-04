#!/usr/bin/python

"""
    Produce a page showing currently downloading torrents from
    files produced by in.ctcs
"""

WORKING_DIRECTORY = "/tmp"

import os

class Torrent:
    torrent = ""
    peerid = ""
    lastmessage = ""
    dlrate = 0
    ulrate = 0
    dllimit = 0
    ullimit = 0
    total = 0
    have = 0
    available = 0
    downloaded = 0
    uploaded = 0
    seeders = 0
    totalseeders = 0
    leechers = 0
    totalleechers = 0
    connecting = 0
    cacheused = 0
    pct = 0
    availablepct = 0 
    def parse(self, file):
        f = open(file, "r")
        x = f.readlines()
        for s in x:
            if (s.startswith("torrent")): self.torrent = s[s.find(" ")+1:]
            if (s.startswith("peerid")): self.peerid = s[s.find(" ")+1:]
            if (s.startswith("lastmessage")): self.lastmessage = s[s.find(" "):].strip()
            if (s.startswith("dlrate")): self.dlrate = int(s[s.find(" ")+1:])
            if (s.startswith("ulrate")): self.ulrate = int(s[s.find(" ")+1:])
            if (s.startswith("dllimit")): self.dllimit = int(s[s.find(" ")+1:])
            if (s.startswith("ullimit")): self.ullimit = int(s[s.find(" ")+1:])
            if (s.startswith("total ")): self.total = int(s[s.find(" ")+1:])
            if (s.startswith("have")): self.have = int(s[s.find(" ")+1:])
            if (s.startswith("available")): self.available = int(s[s.find(" ")+1:])
            if (s.startswith("downloaded")): self.downloaded = int(s[s.find(" ")+1:])
            if (s.startswith("uploaded")): self.uploaded = int(s[s.find(" ")+1:])
            if (s.startswith("seeders")): self.seeders = int(s[s.find(" ")+1:])
            if (s.startswith("totalseeders")): self.totalseeders = int(s[s.find(" ")+1:])
            if (s.startswith("leechers")): self.leechers = int(s[s.find(" ")+1:])
            if (s.startswith("totalleechers")): self.totalleechers = int(s[s.find(" ")+1:])
            if (s.startswith("connecting")): self.connecting = int(s[s.find(" ")+1:])
            if (s.startswith("cacheused")): self.cacheused = int(s[s.find(" ")+1:])
            if self.total > 0: 
                self.pct = round((float(self.have) / float(self.total)) * 100, 2)
                self.availablepct = round((float(self.available) / float(self.total)) * 100, 2)

def getRowStyle(rowstyle):
    if rowstyle == "odd":
        rowstyle = "even"
    else:
        rowstyle = "odd"
    return rowstyle


print """Content-Type: text/html


<html>
<head>
<title>Torrent Downloads</title>
<meta http-equiv="refresh" content="3" />
<link href="style.css" rel="stylesheet" />

<style>

tr.odd {
}

tr.even {
    background: #E6F2FF;
}

</style>

</head>

<body>

<p><a href="index.html">Home</a> |
<a href="download_new.html">Download Torrent</a> |
<a href="download_dir">View Download Directory</a>
</p>

<center>
<h2>Torrent Downloads</h2>
"""

rowstyle = "odd"
outputheader = False
totaldl = 0
totalul = 0
for file in os.listdir(WORKING_DIRECTORY):
    if file.startswith("in.ctcs") and not file.endswith(".in"):
        if not outputheader:
            print """
            <table border="1">
            <tr>
            <th>File</th>
            <th>Sources</th>
            <th>Available</th>
            <th>Down/Up rate</th>
            <th>Down/Up limit</th>
            <th>Completed (Data Down/Up)</th>
            </tr>
            """
            outputheader = True

        t = Torrent()
        t.parse(WORKING_DIRECTORY + "/" + file)
        totaldl += t.dlrate
        totalul += t.ulrate
        rowstyle = getRowStyle(rowstyle)
        print """
        <tr class="%s">
        <td>%s<br/>
        <font color="red">%s</font></td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td><b>%s</b></td>
        <td>
    <a href="download_ctl.cgi?action=CTUPDATE&pid=%s">Find more peers</a><br/>
    <a href="download_ctl.cgi?action=CTRESTART&pid=%s">Reconnect</a><br/>
    <a href="download_ctl.cgi?action=CTQUIT&pid=%s">Cancel</a><br/>
        </td>
        </tr>
        """ % (
            rowstyle,
            t.torrent,
            t.lastmessage,
            "S: " + str(t.seeders) + " of " + str(t.totalseeders) + "<br/>L: " + str(t.leechers) + " of " + str(t.totalleechers) + "<br/>C: " + str(t.connecting), 
            str(t.availablepct) + "&#37;", 
            str(t.dlrate / 1024) + "Kb/" + str(t.ulrate / 1024) + "Kb",
            str(t.dllimit / 1024) + "Kb/" + str(t.ullimit / 1024) + "Kb",
            str(t.pct) + "&#37; (" + str(t.downloaded / 1024 / 1024) + "MB/" + str(t.uploaded / 1024 / 1024) + "MB)",
            file,
            file,
            file)


if not outputheader:
    print """
    <p>No torrent downloads in progress.</p>
    """
else:
    print """
            <tr>
            <td></td>
            <td></td>
            <td></td>
            <td>%sKb/%sKb</td>
            <td></td>
            <td></td>
            </tr>
    </table>
    <p style="font-size: 80%%">(commands may take a couple of seconds to take effect)</p>
    """ % ( str(totaldl / 1024), str(totalul / 1024) )

print """
<hr />
<p style="font-size: 80%">Powered by <a href="http://inetdxtra.sf.net">inetdxtra/in.ctcs</a>.</p>
</center>
</body>
</html>
"""

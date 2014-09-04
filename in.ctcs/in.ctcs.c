/*
 in.ctcs.c
 Copyright(c)2008, R. Rawson-Tetley

 Simple CTCS server for enhanced CTorrent clients. Writes status
 info to readable files in /tmp for use by other applications
 (example CGI interface supplied).

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; either version 2 of
 the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the
 Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston
 MA 02111-1307, USA.

 Contact me by electronic mail: bobintetley@users.sourceforge.net
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>

// The name of the temporary file used for status updates
#define STATUS_FILE "/tmp/in.ctcs.%d"
#define INPUT_FILE "/tmp/in.ctcs.%d.in"
#define WORKING_FOLDER "/tmp"

// How many bandwidth messages we receive before requesting a
// full update from the client
#define FIRE_UPDATE 20

// Time in seconds between updates to the status file
#define FILE_UPDATE 2

// Time in seconds between firing CTUPDATE or CTRESTART messages
// if the download rate falls below 5Kb/s and 2Kb/s respectively
#define UPDATE_INTERVAL 300

// Incoming buffer
char buf[1024];

// Output buffer
char out[2048];

// Limits (passed on command line)
int download_limit = 65535;
int upload_limit = 32768;

// When setting/calculating new limits
int new_dl = 0;
int new_ul = 0;

// CTORRENT parsing
char peerid[50];
long int starttime;
long int currenttime;
char torrentfile[255];

// CTBW parsing
int dlrate;
int ulrate;
int dllimit;
int ullimit;

// CTINFO parsing
char lastmessage[1024];

// CTSTATUS parsing
int seeders;
int totalseeders;
int leechers;
int totalleechers;
int connecting;
int nhave;
int ntotal;
int navail;
long int dltotal;
long int ultotal;
int cacheused;

// How many CTBW messagse we've had
int ctbw = 0;

// Number of running instances
int ctcs_servers = 0;

// download_limit / ctcs_servers
int equal_download_limit = 0;

// Amount of unused bandwidth in other downloads
int unused_bandwidth = 0;

// Status file name
char filename[255];

// Input file name
char infilename[255];

// Process name
char processname[255];

// The last time we forced a CTUPDATE or CTRESTART
time_t lastupdate;

// The last time we wrote to the status file
time_t lastfile;

// Returns the number of ctorrent instances
int get_ctcs_instances() {
    ctcs_servers = 0;
    DIR* d;
    struct dirent *ds;
    d = opendir(WORKING_FOLDER);
    while ((ds = readdir(d)) != NULL) {
        if (strstr(ds->d_name, "in.ctcs") && !strstr(ds->d_name, ".in")) {
            ctcs_servers++;
        }
    }
    closedir(d);
    
    // We might not have finished starting up yet, in which
    // case we'll get a divide by zero calculating bandwidth
    if (ctcs_servers == 0) ctcs_servers = 1;

    return ctcs_servers;
}

// Returns the unused bandwidth from other downloads (in bytes). 
// This is done by reading the status file for each and ignoring
// our file. The amount returned is the total of 
// equal_download_limit - unused_amount for each download
// If a download has more than the equal limit, that amount is
// subtracted to keep us within download_limit overall.
int get_unused_bandwidth() {
    unused_bandwidth = 0;
    DIR* d;
    FILE* f;
    char line[1024];
    char ourpid[8];
    char fname[255];
    int drate;
    sprintf(ourpid, "%d", getpid());
    struct dirent *ds;
    d = opendir(WORKING_FOLDER);
    while ((ds = readdir(d)) != NULL) {
        if (strstr(ds->d_name, "in.ctcs") && !strstr(ds->d_name, ".in")) {
            // Is this our file? Ignore if it is
            if (!strstr(ds->d_name, ourpid)) {
                // Ok, open the file and find the dlrate line
                sprintf(fname, "%s/%s", WORKING_FOLDER, ds->d_name);
                f = fopen(fname, "r");
                while (!feof(f)) {
                    fgets(line, sizeof(line), f);
                    if (strstr(line, "dlrate")) {
                        
                        // We have the line, parse the download rate
                        sscanf(line, "dlrate %d", &drate);

			// Don't take bandwidth from downloads 
			// already near their limit
			if (drate >= (equal_download_limit - 1024))
			    break;

                        // Calculate how much bandwidth is unused by
                        // this download and add it to our running
                        // total. 
                        unused_bandwidth += equal_download_limit - drate;
                        break;
                    }
                }
                fclose(f);
            }
        }
    }
    closedir(d);

    // Don't take all the unused bandwidth - just a share of it so
    // other downloads can have some.
    unused_bandwidth /= (ctcs_servers - 1);
    return unused_bandwidth;
}


// Converts cr/lf into string terminators
char* strip_term(char* str) {
    char* s;
    s = strstr(str, "\r");
    if (s != NULL) *s = '\0';
    s = strstr(str, "\n");
    if (s != NULL) *s = '\0';
    return str;
}

// Clears the input file
void blank_input_file() {
    FILE* f = fopen(infilename, "w");
    flock(f, LOCK_EX);
    fclose(f);
}

// Checks the input file for any messages for the
// ctorrent client and passes them on
void check_incoming() {
    FILE* f = fopen(infilename, "r");
    while (!feof(f)) {
        fgets(buf, sizeof(buf), f);
        printf(buf);
    }
    fclose(f);

    // Clear file once messages sent
    blank_input_file();
}

// Writes an update to the status file
void update_file() {
    
    // Only update the file every 2 seconds at most
    if (difftime(time(NULL), lastfile) <= FILE_UPDATE) return;

    lastfile = time(NULL);
    FILE* f = fopen(filename, "w");
    flock(f, LOCK_EX);
    fprintf(f, "torrent %s\n", torrentfile);
    fprintf(f, "peerid %s\n", peerid);
    fprintf(f, "lastmessage %s\n", lastmessage);
    fprintf(f, "dlrate %d\n", dlrate);
    fprintf(f, "ulrate %d\n", ulrate);
    fprintf(f, "dllimit %d\n", dllimit);
    fprintf(f, "ullimit %d\n", ullimit);
    fprintf(f, "total %d\n", ntotal);
    fprintf(f, "have %d\n", nhave);
    fprintf(f, "available %d\n", navail);
    fprintf(f, "downloaded %ld\n", dltotal);
    fprintf(f, "uploaded %ld\n", ultotal);
    fprintf(f, "seeders %d\n", seeders);
    fprintf(f, "totalseeders %d\n", totalseeders);
    fprintf(f, "leechers %d\n", leechers);
    fprintf(f, "totalleechers %d\n", totalleechers);
    fprintf(f, "connecting %d\n", connecting);
    fprintf(f, "cacheused %d\n", cacheused);
    fclose(f);
}

int main(int argc, char* argv[]) {

    // Parse our command line arguments
    if (argc < 3) {
        printf("Usage: %s download_limit_in_kb upload_limit_in_kb\n", argv[0]);
        exit(1);
    }
    download_limit = atoi(argv[1]);
    download_limit *= 1024;
    upload_limit = atoi(argv[2]);
    upload_limit *= 1024;
    lastupdate = time(NULL);
    lastfile = time(NULL);
    *lastmessage = '\0';

    // Filename to put status in
    sprintf(filename, STATUS_FILE, getpid());

    // Input file (create it empty)
    sprintf(infilename, INPUT_FILE, getpid());
    blank_input_file();

    // Read next message
    while (1) {
        if (!fgets(buf, sizeof(buf), stdin)) {
            // Connection closed
            remove(filename);
            remove(infilename);
            exit(0);
        }

        // CTORRENT message
        if (strncmp(buf, "CTORRENT", 8) == 0) {
            
            // Parse the torrent message
            sscanf(buf, "CTORRENT %s %ld %ld %s", peerid, &starttime, &currenttime, torrentfile);

            // Update the process name
            #ifdef UPDATEPS
            sprintf(processname, "in.ctcs: %s", torrentfile);
            strcpy(argv[0], processname); // deliberate overflow - we don't need env
            #endif

        }

        // CTBW message
        if (strncmp(buf, "CTBW", 4) == 0) {

            // Parse the current bandwidth
            sscanf(buf, "CTBW %d,%d %d,%d", &dlrate, &ulrate, &dllimit, &ullimit);

            // every FIRE_UPDATE bandwidth messages, ask for a status update
            ctbw++;
            if (ctbw == FIRE_UPDATE) {
                ctbw = 0;
                printf("SENDSTATUS\n");
                fflush(stdout);
            }
        }

        // CTINFO message
        if (strncmp(buf, "CTINFO", 6) == 0) {
            strcpy(lastmessage, (buf + 7));
            strip_term(lastmessage);
        }

        // If the download speed has fallen to below 2Kb/s
        // and it's been more than UPDATE_INTERVAL seconds since we last 
        // tried an update - tell the client to reconnect to the 
        // tracker as a new client to get fresh peers
        if (dlrate < (2 * 1024) && difftime(time(NULL), lastupdate) > UPDATE_INTERVAL) {
            printf("CTRESTART\n");
            fflush(stdout);
            lastupdate = time(NULL);
        }

        // If the download speed has fallen to below 5Kb/s
        // and it's been more than UPDATE_INTERVAL seconds since we last 
        // tried an update - tell the client to try and get more peers from 
        // the tracker to bump the speed up a bit.
        if (dlrate < (5 * 1024) && difftime(time(NULL), lastupdate) > UPDATE_INTERVAL) {
            printf("CTUPDATE\n");
            fflush(stdout);
            lastupdate = time(NULL);
        }

        // CTSTATUS message
        if (strncmp(buf, "CTSTATUS", 8) == 0) {

            // Parse the status
            sscanf(buf, "CTSTATUS %d:%d/%d:%d/%d %d/%d/%d %d,%d %ld,%ld %d,%d %d", &seeders, &totalseeders, &leechers, &totalleechers, &connecting, &nhave, &ntotal, &navail, &dlrate, &ulrate, &dltotal, &ultotal, &dllimit, &ullimit, &cacheused);

            // Count the number of running ctcs servers and
            // calculate the equal download bandwidth limit
            equal_download_limit = download_limit / get_ctcs_instances();

            // For uploads, just split the bandwidth equally
            new_ul = upload_limit / ctcs_servers;

            // For downloads, are we bumping up against that equal
            // limit and there's another download we might get
	    // bandwidth from?
            if (dlrate >= (equal_download_limit - 1024) && ctcs_servers > 1) {
                // Calculate how much unused bandwidth there
                // is from the other downloads and pinch it
                new_dl = equal_download_limit + get_unused_bandwidth();
            }
            else {
                // No, just give us the equal share
                new_dl = download_limit / ctcs_servers;
            }

            // Update
            printf("SETDLIMIT %d\n", new_dl);
            printf("SETULIMIT %d\n", new_ul);
            fflush(stdout);

        }

        // Update the file
        update_file();

        // Look for any incoming messages to pass on
        check_incoming();

    }

}

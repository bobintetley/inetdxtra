/*
 
 in.smtp.c
 Copyright(c)2008, R. Rawson-Tetley

 Simple, SMTP relay for use with inetd and my
 NSLU2 (slug) - I use this to receive outbound mail from
 my network machines and then resend them via the system 
 sendmail binary (effectively a smarthost and I use ssmtp
 instead of sendmail on my slug).

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

#ifdef LOGGING
#include <syslog.h>
#endif
#ifdef ONELOG
#include <syslog.h>
#endif

// The date format to use when writing Received headers
#define DATE_FORMAT "%d %b %Y %H:%M:%S %z"

// The name of the temporary file used for message bodies
#define DATA_FILE "/tmp/in.smtp.data.%d"

// The sendmail binary (%s is recipient list)
#define SEND_MAIL "/usr/sbin/sendmail -- %s"

// Incoming buffer
char buf[1024];
// The HELO given by the connected server
char helo[255];
// Our received header (prepended to the mail data)
char recheader[255];
// The date/time of receipt
char recdatetime[64];
// The machine's hostname
char hostname[64];
// The machine's unix name
char uname[64];

// Who the mail is from
char from[255];
// The last recipient we were given
char lastto[255];
// The list of recipients
char to[1024];
// The number of recipients
char toc = 0;

// Handle to file containing DATA portion
FILE* f;
char dataname[255];

// Returns the system date time in a mailheader friendly
// string format (populates recdatetime and returns it)
char* get_date_time() {
    time_t now;
    now = time(NULL);
    strftime(recdatetime, sizeof(recdatetime), DATE_FORMAT, localtime(&now));
    return recdatetime;
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

char* get_command_output(char* dest, char* command) {
    FILE* f = popen(command, "r");
    fgets(dest, 64, f);
    pclose(f);
    return strip_term(dest);
}

// Sends the mail on via the system sendmail binary. Returns
// zero for success, nonzero for an error.
int send_mail() {

    char sendmail[2048];
    char buffer[1024];
    int retval;

    // Send via sendmail/popen
    sprintf(sendmail, SEND_MAIL, to);
    FILE* p = popen(sendmail, "w");

    // Stream the file to the process
    FILE* f = fopen(dataname, "r");
    while (!feof(f)) {
        fgets(buffer, sizeof(buffer), f);
        fprintf(p, buffer);
    }
    
    // Remove the file
    fclose(f);
    remove(dataname);

    // Close the process and get return value
    retval = pclose(p);

    if (!retval) {
        printf("250 Ok resent via sendmail\n");
        fflush(stdout);
        #ifdef ONELOG
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_INFO), "OK from=%s to=%s (helo %s)", from, to, helo);
        #endif
    }
    else {
        printf("550 sendmail returned an error\n");
        fflush(stdout);
        #ifdef ONELOG
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "ERROR from=%s to=%s (helo %s)", from, to, helo); 
        #endif
    }
    return retval;
}

// Looks in the buffer for an email address inside 
// angle brackets. If the address was understood,
// a 250 message is sent and a non-zero value returned.
// dest is where to store the address
int parse_address(char* dest) {

    char* start;
    char* end;
    int len = 0;
    int ok = 0;

    start = strstr(buf, "<");
    end = strstr(buf, ">");
    ok = ( start != NULL && end != NULL ? 1 : 0 );

    // Copy it to dest
    len = end - start;
    strncpy(dest, (char*) start + 1, len);
    end = strstr(dest, ">");
    *end = '\0';

    if (strstr(dest, "@")) {
        printf("250 Ok (%s)\n", dest);
        fflush(stdout);
        return 1;
    }
    else {
        printf("550 Invalid mailbox '%s'\n", dest);
        fflush(stdout);
        return 0;
    }
}

// Returns the machine's hostname
char* gethostname() {
    return get_command_output(hostname, "hostname");
}

// Returns the operating system
char* getostype() {
    return get_command_output(uname, "uname");
}



int main(int argc, char** argv) {

    // Reset all our strings before we start
    *helo = '\0';
    *recheader = '\0';
    *recdatetime = '\0';
    *from = '\0';
    *lastto = '\0';
    *to = '\0';

    // Filename to put data in
    sprintf(dataname, DATA_FILE, getpid());

    // Send our greeting first
    printf("220 %s SMTP in.smtp (%s)\n", gethostname(), getostype());
    fflush(stdout);

    // SMTP is a 3 stage protocol, the phase tells us where we're
    // at - 
    // 0 = waiting for HELO
    // 1 = waiting for MAIL/RCPT or DATA
    // 2 = receiving data
    int phase = 0;

    while (1) {

        // Read next line from client
        if (NULL == fgets(buf, sizeof(buf), stdin))
            // Connection terminated
            return 1;

        // Phase 0: We're expecting a HELO or a QUIT
        if (phase == 0) {
            if (strncmp(buf, "HELO", 4) == 0) {
                strcpy(helo, (char*) buf+5);
                strip_term(helo);
                printf("250 Hello %s\n", helo);
                fflush(stdout);
                // Pre-generate our received header
                sprintf(recheader, "Received: from %s by %s ; %s\r\n", helo, gethostname(), get_date_time());
                phase++;
            }

            else if (strncmp(buf, "QUIT", 4) == 0) {
                printf("221 Bye\n");
                fflush(stdout);
                return 0;
            }

            else {
                printf("550 I don't understand '%s'\n", buf);
                fflush(stdout);
            }
        }

        // Phase 1: Expecting a MAIL FROM, RCPT TO, DATA or a QUIT
        else if (phase == 1) {
            
            // MAIL - parse the from address
            //
            // MAIL also fulfils a special function in SMTP land and
            // tells us we need to clear out any state from any previous
            // mails (we reset the recipient list to start again)
            if (strncmp(buf, "MAIL", 4) == 0) {
                if (parse_address(from)) {
                    toc = 0;
                    *to = '\0';
                }
            }

            // RCPT - parse the to and add it to our list of recipients
            else if (strncmp(buf, "RCPT", 4) == 0) {
                if (parse_address(lastto)) {
                    strcat(to, " ");
                    strcat(to, lastto);
                    toc++;
                }
            }

            // DATA - start accepting the file data
            else if (strncmp(buf, "DATA", 4) == 0) {
                
                // If we haven't got a source or recipient, then
                // we have to fail as we don't know what to do with
                // the mail
                if (!from || toc == 0) {
                    printf("550 Missing recipient/sender\n");
                    fflush(stdout);
                    phase = 1;
                }

                // We're good, tell them we're ready to accept
                // some data.
                printf("354 End data with <CRLF>.<CRLF>\n");
                fflush(stdout);
                f = fopen(dataname, "wb");
                // Add our received header before the other data
                fprintf(f, recheader);
                phase++;
            }

            else if (strncmp(buf, "QUIT", 4) == 0) {
                printf("221 Bye\n");
                fflush(stdout);
                return 0;
            }

            else {
                printf("550 I don't understand '%s'\n", buf);
                fflush(stdout);
            }

        }

        // Phase 2: Receiving mail data
        else if (phase == 2) {
            
            // Terminating? Close our file and send the mail
            if (strncmp(buf, ".", 1) == 0 && strlen(buf) < 4) {
                phase++;
                fclose(f);
                send_mail();
                phase = 1;
            }

            // Receiving a data chunk - stream it out to our file
            fprintf(f, buf);
        }
    }
}

/*
 
 in.proxy.c
 Copyright(c)2009, R. Rawson-Tetley

 Simple HTTP proxy for inetd and the NSLU2. Does not
 support caching or the CONNECT method.

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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#ifdef LOGGING
#include <syslog.h>
#endif

#define COMBINEDFMT "%d/%b/%Y:%H:%M:%S %z"
#define LOGFILE "/var/log/in.proxy.log"
#define SOCKET_TIMEOUT_SECS 2
#define CONNECT_TIMEOUT_MS 10000

// Input buffer size
#define TOKEN_SIZE 4096

// Buffer for request (512Kb)
#define REQUEST_SIZE 1024 * 512

char url[TOKEN_SIZE];

#define STDIN 0
#define READ 0
#define WRITE 1

#ifdef ONELOG
// Simple logger, outputs in combined format
void logrequest(int code) {

    // Get the IP address
    struct sockaddr_in from;
    int fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    getpeername(STDIN, (struct sockaddr *) &from, &fromlen);

    // Generate the log date
    char timebuf[128];
    time_t now;
    now = time(NULL);
    strftime(timebuf, sizeof(timebuf), COMBINEDFMT, localtime(&now));

    // Content length
    char* clen = "-";

    // Refer and user agent
    char* referer = "-";
    char* useragent = "-";
    char* ip = inet_ntoa(from.sin_addr);
    
    // Write to the file
    FILE* f = fopen(LOGFILE, "a");
    fprintf(f, "%s - - [%s] \"%s\" %d %s \"%s\" \"%s\"\n", ip, timebuf, url, code, clen, referer, useragent);
    fclose(f);
}
#endif

void send_error(char* message, int code) {
    printf("Error: %d\r\n\r\n%s", code, message);
    fflush(stdout);
    // Log it if we need to
    #ifdef ONELOG
        logrequest(code);
    #endif

}

void handle_connect(char* url) {
 
    char host[TOKEN_SIZE];
    int port = 443;
    struct hostent* hp;
    struct sockaddr_in addr;
    int on = 1, sock;

    // The url should be a host with a port, split them up
    strcpy(host, url);
    char* colonsplit = (char*) strchr(host, ':');
    *colonsplit = '\0';
    port = atoi(strchr(url, ':') + 1);

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Resolving host %s", host);
    #endif

    if ((hp = gethostbyname(host)) == NULL) {
        send_error("Couldn't resolve host.", 404);
        return;
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Creating target address");
    #endif

    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Creating socket");
    #endif

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Setting socket options");
    #endif

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof(int));
    if (sock == -1) {
        send_error("Failed creating socket.", 500);
        return;
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Connecting socket");
    #endif

    if (connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) == -1) {
        send_error("Failed connecting socket.", 500);
        return;
    }

    // Return a 200 OK to the client - we have their connection
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Sending 200 to client - connection established");
    #endif
    printf("HTTP/1.0 200 Connection established\r\n\r\n");
    fflush(stdout);

    // Log the request
    #ifdef ONELOG
        logrequest(200);
    #endif

    // Make stdin and our socket non-blocking
    fcntl(STDIN, F_SETFL, fcntl(STDIN, F_GETFL) | O_NONBLOCK);
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);

    // Echo input received from stdin to the socket and echo 
    // input received from the socket to stdout until one side
    // is closed.
    char buf[TOKEN_SIZE];
    int sz = 0;
    int totaltime = 0; // Total time without data in ms
    while (1) {

        // Read from stdin and echo it to the socket
        sz = fread(buf, 1, TOKEN_SIZE -1, stdin);
        if (sz < 0) {
            if (errno != EWOULDBLOCK) {
             #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Client connection broken, exiting", sz);
            #endif
            return;
            }
        }
        else if (sz > 0) {
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Read %d bytes from stdin, echoing to socket", sz);
            #endif
            send(sock, buf, sz, 0);
            totaltime = 0;
        }

        // Wait for some more data
        usleep(50000);

        // Read from socket and echo it to stdout
        sz = recv(sock, buf, TOKEN_SIZE -1, 0);
        if (sz < 0) {
            if (errno != EWOULDBLOCK) {
                 #ifdef LOGGING
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Connection to remote server broken, exiting", sz);
                #endif
                return;
            }
        }
        else if (sz > 0) {
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Read %d bytes from socket, echoing to stdout", sz);
            #endif
            fwrite(buf, 1, sz, stdout);
            fflush(stdout);
            totaltime = 0;
        }

        // Wait for some more data
        usleep(50000);

        // Update time so far without data (100,000 microseconds = 100ms)
        totaltime += 100;

        // Has our timeout expired?
        if (totaltime >= CONNECT_TIMEOUT_MS) {
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CONNECT data timeout of %dms exceeded, closing sockets", CONNECT_TIMEOUT_MS);
            #endif
            close(sock);
            return;
        }

    }

}

void make_request(char* host, char* request) {
 
    struct hostent* hp;
    struct sockaddr_in addr;
    int on = 1, sock;

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Resolving host %s", host);
    #endif

    if ((hp = gethostbyname(host)) == NULL) {
        send_error("Couldn't resolve host.", 404);
        return;
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Creating target address");
    #endif

    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(80);
    addr.sin_family = AF_INET;

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Creating socket");
    #endif

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Setting socket options");
    #endif

    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *) &on, sizeof(int));
    if (sock == -1) {
        send_error("Failed creating socket.", 500);
        return;
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Connecting socket");
    #endif

    if (connect(sock, (struct sockaddr*) &addr, sizeof(struct sockaddr_in)) == -1) {
        send_error("Failed connecting socket.", 500);
        return;
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Sending request: %s", request);
    #endif
   
    // Send the request
    write(sock, request, strlen(request));

    char buf[TOKEN_SIZE];

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Reading and sending response");
    #endif

    // Set up select() wait variables
    fd_set rfds; 
    struct timeval tv; 

    // Read the response and pump it back to the client
    int sz = 0;
    while (1) {
        sz = recv(sock, buf, TOKEN_SIZE -1, 0);
        if (sz <= 0) break;
        fwrite(buf, 1, sz, stdout);
        fflush(stdout);

        #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CHUNK (%d bytes): %s", sz, buf);
        #endif
        bzero(buf, TOKEN_SIZE);
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Closing socket");
    #endif

    shutdown(sock, SHUT_RDWR);
    close(sock);

    // Log it if we need to
    #ifdef ONELOG
        logrequest(200);
    #endif

}

int process()
{
    char buf[TOKEN_SIZE];
    char request[REQUEST_SIZE];
    char host[TOKEN_SIZE];
    char method[TOKEN_SIZE];
    char httpver[TOKEN_SIZE];

    // Grab the first line - should be the GET request
    if (!fgets(buf, sizeof(buf), stdin)) return -1;

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "REQUEST: %s", buf);
    #endif

    // Parse the request line
    char* c = strtok(buf, " ");
    strcpy(method, c);
    c = strtok(NULL, " ");
    strcpy(url, c);
    c = strtok(NULL, " ");
    strcpy(httpver, c);

    // Handle CONNECT differently from normal HTTP requests
    if (strncmp(buf, "CONNECT", 7) == 0) {
        #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CONNECT: %s", url);
        #endif

        // Read and throw away the rest of the request
        while (fgets(buf, TOKEN_SIZE, stdin))
           if (*buf == '\r' || *buf == '\n') break;

        handle_connect(url);
        return 0;
    }

    // Extract the host portion
    c = strstr(url, "://");
    c += 3;
    char* h = host;
    while (*c != '/')
        *h++ = *c++;
    *h = '\0';

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "TARGETHOST: %s", host);
    #endif

    // Construct a new request line for the target host without the http://host bit
    sprintf(request, "%s %s %s", method, c, httpver);

    // Now get the rest of the request
    while (fgets(buf, TOKEN_SIZE, stdin)) {
        
        // stop when we get a blank, but still add the final terminator and
        // tell the server we want the connection closed
        if (*buf == '\r' || *buf == '\n') {
            strcat(request, "Connection: close\r\n\r\n");
            break;
        }

        // Filter out Proxy-Connection and Connection headers
        if (strstr(buf, "Proxy-Connection:") == NULL && strstr(buf, "Connection:") == NULL)
            strcat(request, buf);
    }

    // Are we POSTing? If so, there's more request, grab it
    if (strncmp(method, "POST", 4) == 0) {

        // Make stdin non-blocking
        fcntl(STDIN, F_SETFL, fcntl(STDIN, F_GETFL) | O_NONBLOCK);

        while (fgets(buf, TOKEN_SIZE, stdin)) {
            if (*buf == '\r' || *buf == '\n') break;
            strcat(request, buf);
        }
    }

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "TRANSMIT: %s", request);
    #endif

    // Connect to the host and make the request
    make_request(host, request);

    return 0;
}

int main(int argc, char* argv[])
{
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "in.proxy loaded");
    #endif
    return process();
}

/*
 * in.dns - a miniscule DNS server that runs
 * through inetd.
 *
 * Supports A and PTR records and has a simple configuration
 * file in the format:
 *
 * myhost.mydomain.             10.0.0.1
 * otherhost.otherdomain.       192.168.82.15
 *
 * Author: Robin Rawson-Tetley
 * Licence: GPLv2
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#ifdef USE_NSS
#include <netdb.h>
#include <arpa/inet.h>
#endif

#ifdef LOGGING
#include <syslog.h>
#endif

#define CONFIG "/etc/in.dns.conf"
#define STDIN 0
#define STDOUT 1

char packet[1024];
int endmarker = 0;
char response[1024];
struct sockaddr_in from;
size_t fromlen;

int gotanswer = 0;
int ip_lookup = 1;

char qhost[512];
char rhost[512];
char rddata[512];

// Gets the IP and source port
void populate_address() {
    fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    getpeername(STDIN, (struct sockaddr *) &from, &fromlen);
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "DNS packet from %s:%d", inet_ntoa(from.sin_addr), from.sin_port);
    #endif
}

// Receives the packet data
int recv_data() {
    return recvfrom(STDIN, packet, sizeof(packet), MSG_WAITALL, &from, &fromlen);
}

// Lookup hostname
char* lookup_hostname() {

#ifndef USE_NSS
    char line[255];
    char host[192];
    char address[64];
#endif
    char searchadd[64];

    *rhost = '\0';

    // Is this a reverse lookup? If so, reformat the address
    // into something we can compare with our config file
    if (strstr(qhost, "arpa")) {
        ip_lookup = 0;
        // Strip the in-addr bit and reverse
        // the IP address order for comparision
        char* ip0;
        char* ip1;
        char* ip2;
        char* ip3;
        ip0 = strtok(qhost, ".");
        ip1 = strtok(NULL, ".");
        ip2 = strtok(NULL, ".");
        ip3 = strtok(NULL, ".");
        sprintf(searchadd, "%s.%s.%s.%s", ip3, ip2, ip1, ip0);
    }

    #ifndef USE_NSS

        // Open up our file and find the hostname
        FILE* f = fopen(CONFIG, "r");
        while (!feof(f)) {
            
            fgets(line, 255, f);

            // Skip comments
            if (strstr(line, "#")) continue;

            // Split the line into host/address
            sscanf(line, "%s %s", host, address);

            // Is this a reverse (PTR record) lookup
            if (!ip_lookup) {
                // Is this the IP address requested?
                if (strcmp(searchadd, address) == 0) {
                    #ifdef LOGGING
                        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Found PTR record for '%s' at '%s'", address, host);
                    #endif
                    gotanswer = 1;
                    strcpy(rhost, host);
                    break;
                }
            }
            // It's an IP (A record) lookup
            else {
                // Is this the hostname requested?
                if (strcmp(qhost, host) == 0) {
                    #ifdef LOGGING
                        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Found A record for '%s' at '%s'", host, address);
                    #endif
                    gotanswer = 1;
                    strcpy(rhost, address);
                    break;
                }
            }
        }
        fclose(f);

    #else /* USE_NSS */

        if (ip_lookup) {
            struct hostent *e;
            int x = strlen(qhost);
            if (qhost[x-1] == '.') qhost[x-1] = '\0';
            if ((e = gethostbyname(qhost)) != NULL) {
                struct in_addr iaddr = *(struct in_addr*)e->h_addr;
                strcpy(rhost, inet_ntoa(iaddr));
                gotanswer = 1;
            }
        } else {
            struct hostent *e;
            struct in_addr iaddr;
            if (inet_aton(searchadd, &iaddr)) {
                if ((e = gethostbyaddr(&iaddr, sizeof(iaddr), AF_INET)) != NULL) {
                    int i = strlen(e->h_name);
                    strcpy(rhost, e->h_name);
                    if(rhost[i] != '.')
                        rhost[i] = '.';
                    gotanswer = 1;
                }
            }
        }

    #endif /* USE_NSS */

    #ifdef LOGGING
        if (!gotanswer) {
            if (ip_lookup)
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Couldn't find an A record for '%s'", qhost);
            else
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Couldn't find a PTR record for '%s'", searchadd);
        }
    #endif

    return rhost;

}

// Returns the hostname the client is requesting
char* parse_udp_packet() {
    
    char chunk[255];
    int i, x, len;
    *qhost = '\0';

    // QNAME starts at byte 12
    i = 12;
   
    while (1) {

        // Get length of next chunk of hostname
        len = (int) *(packet + i);
        
        // If we get a zero, that's the end
        if (!len) break;

        // Grab the chunk
        i++;
        for (x = 0; x < len; x++) {
            *(chunk + x) = *(packet + i + x);
        }
        *(chunk + len) = '\0';

        // Add it into our host
        strcat(qhost, chunk);
        strcat(qhost, ".");

        // Move to the next chunk
        i += len;

    }
    
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Got QNAME from packet: %s", qhost);
    #endif

    // Set the end marker - it will be the zero that we read
    // plus 4 bytes to skip the query type/class. We need
    // the end marker so we know where to put our answer
    // section for the response
    endmarker = i + 5;

    return qhost;
}

// Creates the RDDATA for an IP address
char* create_rddata_ip(char* s) {

    *(rddata + 4) = '\0';

    char add[64];
    strcpy(add, s);

    int i = 0;
    int ri = 0;
    int len = strlen(add);
    char* lastnum = add;
    
    for (i = 0; i < len; i++) {
        if (*(add + i) == '.' || i == (len - 1)) {

            // Make the dot into a terminator and
            // turn it into a number
            *(add + i) == '\0';
            *(rddata + ri) = (char) atoi(lastnum);

            // Next position
            ri++;
            lastnum = add + i + 1;
        }
    }

    return rddata;
}

// Creates the RDDATA for a hostname
char* create_rddata_hostname(char* s) {

    // Copy the rhost to rddata, but offset by one byte so
    // we can put the first chunk length there
    *rddata = ' ';
    strcpy(rddata + 1, s);

    int i = 0;
    int len = 0;

    // Count backwards through the string and replace
    // any dots we find with the length since the last
    // dot or the end of the string.
    for (i = strlen(rddata) - 1; i >= 0; i--) {

        // We have a dot, or it's the beginning of the
        // string. Replace it with the counted length
        if (*(rddata + i) == '.' || i == 0) {
            *(rddata + i) = (char) len;
            len = 0;
        }
        else {
            len++;
        }
    }
    return rddata;
}

// Reads the hostname we have and creates the rddata buffer
// containing the name in DNS format (chunklength, chunk...)
char* create_rddata(char* s) {
    if (ip_lookup)
        return create_rddata_ip(s);
    else
        return create_rddata_hostname(s);
}


char* send_response() {

    // If we don't have an answer, send an empty packet so
    // the client thinks we're lame and tries the next nameserver
    // (must be a better way than this?)
    if (!gotanswer) {
        sendto(STDOUT, packet, 1, 0, &from, fromlen);
        return;
    }

    // Flip the header to be a query response
    *(packet + 2) = (char) 0x85;

    // We only send 1 answer
    *(packet + 7) = (char) 1;

    // Add the answer section to the packet, starting
    // at the endmarker
    int i = endmarker;

    // Pointer to the name in the query
    *(packet + i) = 0xC0; i++;
    *(packet + i) = 0x0C; i++;

    // TYPE 
    if (ip_lookup) {
        // 0001 == A
        *(packet + i) = 0x00; i++;
        *(packet + i) = 0x01; i++;
    }
    else {
        // 000C == PTR
        *(packet + i) = 0x00; i++;
        *(packet + i) = 0x0C; i++;
    }

    // CLASS (0001 == INTERNET)
    *(packet + i) = 0x00; i++;
    *(packet + i) = 0x01; i++;

    // TTL
    *(packet + i) = 0x00; i++;
    *(packet + i) = 0x00; i++;
    *(packet + i) = 0x00; i++;
    *(packet + i) = 0x3C; i++;

    // RDLENGTH and RRDATA
    if (ip_lookup) {
        // A RECORD
        // RDLENGTH
        *(packet + i) = 0x00; i++;
        *(packet + i) = 0x04; i++;
        // RRDATA
        memcpy( (packet + i), rddata, 4);
        i += 4;
    }
    else {
        // PTR RECORD
        // RDLENGTH
        *(packet + i) = strlen(rddata) / 256; i++;
        *(packet + i) = (strlen(rddata) % 256) + 1; i++;
        // RRDATA
        memcpy( (packet + i), rddata, strlen(rddata) + 1);
        i += strlen(rddata) + 1;
    }

    // FCS
    *(packet + i) = 0xC8; i++;
    *(packet + i) = 0x4C; i++;

    // STOP
    *(packet + i) = 0x7E; i++;

    #ifdef PACKETDUMP
        FILE* f = fopen("/tmp/in.dns.dump", "w");
        fwrite(packet, sizeof(char), i, f);
        fclose(f);
    #endif

    // Send the response
    sendto(STDOUT, packet, i, 0, &from, fromlen);
}

int main() {

    // Die if idle for a bit
    alarm(10);

    // Get address
    populate_address();

    // Receive UDP data
    recv_data();

    // Parse the query
    parse_udp_packet();

    // Lookup the qname
    lookup_hostname();

    // Generate rddata for response
    create_rddata(rhost);

    // Send the response
    send_response();

    exit(0);

}

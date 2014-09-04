/*
 * in.dhcp - a lightweight DHCP server that runs
 * through inetd.
 *
 * Supports ipv4 for a single subnet, DHCPOFFER/ACK, pools
 * and static leases and full DHCP options.
 *
 * Author: Robin Rawson-Tetley
 * Date:   September 2008
 *
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#ifdef LOGGING
#include <syslog.h>
#endif

#ifdef ONELOG
#include <syslog.h>
#endif

#define CONFIG "/etc/in.dhcp.conf.%s"
#define LEASES "/tmp/in.dhcp.leases.%s"
#define INBOUND_PACKET "/tmp/in.dhcp.in"
#define OUTBOUND_PACKET "/tmp/in.dhcp.out"

#define STDIN 0
#define STDOUT 1

#define BOOTREQUEST 0x00
#define BOOTREPLY 0x02

#define DHCPDISCOVER 0x01
#define DHCPOFFER 0x02
#define DHCPREQUEST 0x03
#define DHCPDECLINE 0x04
#define DHCPACK 0x05
#define DHCPNAK 0x06
#define DHCPRELEASE 0x07

#define BROADCAST_ADDR "255.255.255.255"
#define BOOTPC 68

// deserialisation macros

#define INT8_TO_BUF(src,dest) \
(dest)[0] = (src); \
(dest) += 1;

#define INT16_TO_BUF(src,dest) \
(dest)[0] = (((src) >> 8) & 0xff); \
(dest)[1] = ((src) & 0xff); \
(dest) += 2;

#define INT32_TO_BUF(src,dest) \
(dest)[0] = (((src) >> 24) & 0xff); \
(dest)[1] = (((src) >> 16) & 0xff); \
(dest)[2] = (((src) >> 8) & 0xff); \
(dest)[3] = ((src) & 0xff); \
(dest) += 4;

#define BUF_TO_INT8(dest,src) \
(dest) = (unsigned char) (src)[0]; \
(src) += 1;

#define BUF_TO_INT16(dest,src) \
(dest) = (((unsigned char)(src)[0] << 8) | (unsigned char)(src)[1]); \
(src) += 2;

#define BUF_TO_INT32(dest,src) \
(dest) = ( ((unsigned char)(src)[0] << 24) | ((unsigned char)(src)[1] << 16) |((unsigned char)(src)[2] << 8) | (unsigned char)(src)[3]); \
(src) += 4;

// option builders - these parse config options and
// add them to the options buffer for including in the
// response packet
#define ADD_IP(name,option) \
if (strcmp(pname, name) == 0) { \
    if (option_set(option)) continue; \
        *p = option; p++; \
        *p = 4; p++; \
        p += addip(p, pvalue); \
        continue; \
}

#define ADD_IPS(name,option) \
if (strcmp(pname, name) == 0) { \
    if (option_set(option)) continue; \
        *p = option; p++; \
        p += addips(p, num_args, pvalue, pvalue2, pvalue3); \
        continue; \
}

#define ADD_STR(name,option) \
if (strcmp(pname, name) == 0) { \
    if (option_set(option)) continue; \
        *p = option; p++; \
        p += addstr(p, pvalue); \
        continue; \
}

#define ADD_BYTE(name,option) \
if (strcmp(pname, name) == 0) { \
    if (option_set(option)) continue; \
        *p = option; p++; \
        *p = 1; p++; \
        *p = (unsigned char) atoi(pvalue); p++; \
        continue; \
}

#define ADD_INT32(name,option) \
if (strcmp(pname, name) == 0) { \
    if (option_set(option)) continue; \
        uint32_t ii; \
        sscanf(pvalue, "%u", &ii); \
        *p = option; p++; \
        *p = 4; p++; \
        p[0] = (ii >> 24) & 0xff; \
        p[1] = (ii >> 16) & 0xff; \
        p[2] = (ii >> 8) & 0xff; \
        p[3] = (ii & 0xff); \
        p += 4; \
        continue; \
}

#define ADD_INT16(name,option) \
if (strcmp(pname, name) == 0) { \
    if (option_set(option)) continue; \
        uint16_t ii; \
        sscanf(pvalue, "%u", &ii); \
        *p = option; p++; \
        *p = 2; p++; \
        p[0] = (ii >> 8) & 0xff; \
        p[1] = (ii & 0xff); \
        p += 2; \
        continue; \
}


        
// Files
char configfile[255];
char leasesfile[255];

// Packet data
unsigned char packet[1024];

// Parsed packet chunks
struct ether_addr clientmac;
uint8_t op;
uint8_t htype;
uint8_t hlen;
uint8_t hops;
uint32_t xid;
uint16_t secs;
uint16_t flags;
uint32_t ciaddr;
uint32_t yiaddr;
uint32_t siaddr;
uint32_t giaddr;
unsigned char chaddr[16];
unsigned char sname[64];
unsigned char file[128];
unsigned char options[312];
uint8_t dhcp_message_type;

char clientmacstr[30];

// Socket gubbins
struct sockaddr_in from;
socklen_t fromlen;

// Options we've already set, so we know to ignore
uint8_t setoptions[100];

// interface we're listening (just the name - it's
// used for config files as inetd/xinetd determine
// the real interface)
char iface[20];

// Address we're bound to - source address for UDP response.
// If not supplied, INADDR_ANY is used
char bindaddress[64];

// IP pool boundaries
uint32_t poolstart;
uint32_t poolend;

// Gets the from address for receiving
void populate_address() {
    fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    getpeername(STDIN, (struct sockaddr *) &from, &fromlen);
}

// Receives the packet data
int recv_data() {
    int sz = recvfrom(STDIN, packet, sizeof(packet), MSG_WAITALL, &from, &fromlen);
    #ifdef PACKETDUMP
        FILE* f = fopen(INBOUND_PACKET, "wb");
        fwrite(packet, sizeof(unsigned char), sz, f);
        fclose(f);
    #endif
    return sz;
}

// Converts an IP address to a 4 byte array and adds
// it to our packet. Returns the length.
int addip(unsigned char* p, char* ip) {
    int i;
    uint32_t add = ntohl(inet_addr(ip));
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Converting ASCII IP '%s' to 32-bit int %08X", ip, add);
    #endif
    INT32_TO_BUF(add, p);
    return 4;
}

// Converts an IP address to a 4 byte array
uint32_t getip(char* ip) {
    uint32_t add = ntohl(inet_addr(ip));
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Converting ASCII IP '%s' to 32-bit int %08X", ip, add);
    #endif
    return add;
}


// pvalue, pvalue2/3 may contain IP addresses, num_args says how
// many. Converts them to 4 byte arrays and adds to our packet.
// Returns the length;
int addips(unsigned char* p, int num_args, char* pvalue, char* pvalue2, char* pvalue3) {
    *p = (unsigned char) (4 * num_args); p++;
    p += addip(p, pvalue); 
    if (num_args > 1) p += addip(p, pvalue2);
    if (num_args > 2) p += addip(p, pvalue3);
    return (num_args * 4) + 1;
}

int addstr(unsigned char* p, char* pvalue) {
    uint8_t len;
    len = strlen(pvalue);
    *p = len; p++;
    memcpy(p, pvalue, len);
    return len + 1;
}


// Returns true if an option has already been set. If not,
// returns false and sets it.
int option_set(uint8_t opt) {
    uint8_t i;
    for (i = 0; i < sizeof(setoptions); i++) {
        if (setoptions[i] == opt) {
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Option %02X already set", opt);
            #endif
            return 1;
        }
        if (setoptions[i] == 0)
            break;
    }
    // i contains last unused spot now
    setoptions[i] = opt;
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Opt %02X not set, setting at position %02X", opt, i);
    #endif
    return 0;
}

// Gets an address from the pool for the client mac address
// given and associates the two forever (until the
// file is removed anyway). If the mac address is
// in the list, we give out the same address again.
//
// If no addresses are available, 0 is returned,
// otherwise a 32-bit ipv4 address is returned
// in host-order.
//
// The file is deliberately ascii for readability
uint32_t get_pool_address() {

    uint32_t i;
    int created = 0;
    char line[255];
    char ip[20];
    char mac[30];

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Looking up pool address for %s", clientmacstr);
    #endif

    FILE* f = fopen(leasesfile, "r");
    if (!f) {
        // The file isn't there, create it
	#ifdef LOGGING
	    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Leases file %s not present, creating it", leasesfile);
	#endif
	f = fopen(leasesfile, "w");
	fclose(f);
	f = fopen(leasesfile, "r");
	created = 1;
    }

    // Scan through the file, looking for our mac address
    // i tracks the next available ip address
    i = poolstart;
    if (!created) {
        while (!feof(f)) {
            fgets(line, 255, f);
            sscanf(line, "%s %s", ip, mac);

            // Does the mac match ours?
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Comparing lease '%s' and client '%s'", mac, clientmacstr);
            #endif
            if (strcmp(clientmacstr, mac) == 0) {
                #ifdef LOGGING
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Found ip address %s for MAC %s (%08x)", ip, mac, i);
                #endif
                // Great, return it
                return i;
            }
            i++;

            // Make sure we don't track an illegal address
            // by skipping again if we hit one (host byte
            // is 255 or 0)
            uint8_t digit4;
            digit4 = i & 0xFF;
            if (digit4 == 0) i++;
            if (digit4 == 0xFF) i += 2;
        }
    }

    // Ok, we're not in the lease file
    fclose(f);

    // Did we go past the end of the pool?
    if (i > poolend)
        // The pool is full
        return 0;

    // i holds the next available address in the pool
    // assign it to this mac and write it to the leases file
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Assign pool IP %s for MAC %s (%08X)", inet_ntoa(htonl(i)), clientmacstr, i);
    #endif
    f = fopen(leasesfile, "a");
    fprintf(f, "%s %s\n", inet_ntoa(htonl(i)), clientmacstr);
    fclose(f);

    return i;
}

// Reads the config file and builds the response
int construct_response() {
    
    char pname[50];
    char pvalue[100];
    char pvalue2[100];
    char pvalue3[100];
    int num_args = 0;
    uint8_t ip[4];
    int fixedip = 0;
    int i = 0;

    // Zero out the options buffer
    memset(options, 0, sizeof(options));
    memset(setoptions, 0, sizeof(setoptions));

    // Grab a pointer to the start of the options 
    unsigned char* p = options;

    // BOOTREPLY type
    op = BOOTREPLY;

    // First option: DHCP Message Type ( 53 )
    *p = 53; p++;
    *p = 1; p ++;

    // Respond to a DHCPDISCOVER with a DHCPOFFER
    // or a DHCPREQUEST with a DHCPACK - options are the same
    if (dhcp_message_type == DHCPDISCOVER) {
        #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Extending DHCPOFFER");
        #endif
        *p = DHCPOFFER; p++;
    }
    else if (dhcp_message_type == DHCPREQUEST) {
        #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Extending DHCPACK");
        #endif
        *p = DHCPACK; p++;
    }
    else {
        #ifdef LOGGING
            syslog(LOG_ERR, "Don't understand DHCP message type %02X - bailing out.", dhcp_message_type);
        #endif
        return 0;
    }

    // String representing client mac address for comparison
    sprintf(clientmacstr, "%02X:%02X:%02X:%02X:%02X:%02X",
            clientmac.ether_addr_octet[0], clientmac.ether_addr_octet[1],
            clientmac.ether_addr_octet[2], clientmac.ether_addr_octet[3],
            clientmac.ether_addr_octet[4], clientmac.ether_addr_octet[5]);
    
    // Read the config file and add options to the packet
    char line[255];
    int skip_block = 0;
    FILE* f = fopen(configfile, "r");
    if (!f) {
        #ifdef LOGGING
        syslog(LOG_ERR, "Config file '%s' not found. Bailing out.", configfile);
        #endif
        return 0;
    }

    while (!feof(f)) {
        
        fgets(line, 255, f);

        // Ignore comments 
        if (strstr(line, "#")) continue;

        // Parameters
        if (!skip_block) {

            // Split the config line
            num_args = sscanf(line, "%s %s %s %s", pname, pvalue, pvalue2, pvalue3);
            if (num_args == 0 || num_args == EOF) continue;
            num_args--; // ignore parameter name

            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Got config param: %s, value: %s, numargs: %d, offset: %u", pname, pvalue, num_args, (p - options));
	    #endif

            ADD_IP("subnet-mask", 1);
            ADD_INT32("time-offset", 2);
            ADD_IPS("routers", 3);
            ADD_IPS("time-servers", 4);
            ADD_IPS("name-servers", 5);
            ADD_IPS("domain-servers", 6);
            ADD_IPS("log-servers", 7);
            ADD_IPS("cookie-servers", 8);
            ADD_IPS("lpr-servers", 9);
            ADD_IPS("impress-servers", 10);
            ADD_IPS("resource-location-servers", 11);
            ADD_STR("hostname", 12);
            ADD_INT16("bootfile-size", 13);
            ADD_STR("merit-dump-file", 14);
            ADD_STR("domain-name", 15);
            ADD_IP("swap-server", 16);
            ADD_STR("root-path", 17);
            ADD_STR("extensions-path", 18);
            ADD_BYTE("ip-forwarding", 19);
            ADD_BYTE("datagram-forwarding", 20);
            ADD_IPS("policy-filter", 21);
            ADD_INT16("maximum-datagram-reassembly", 22);
            ADD_BYTE("default-udp-ttl", 23);
            ADD_INT32("path-mtu-aging-timeout", 24);
            ADD_INT16("path-mtu-plateau", 25);
            ADD_INT16("mtu", 26);
            ADD_BYTE("subnets-are-local", 27);
            ADD_IP("broadcast-address", 28);
            ADD_BYTE("perform-mask-discovery", 29);
            ADD_BYTE("mask-supplier", 30);
            ADD_BYTE("router-discovery", 31);
            ADD_IP("router-solicitation", 32);
            ADD_IPS("static-route", 33);
            ADD_BYTE("trailer-encapsulation", 34);
            ADD_INT32("arp-cache-timeout", 35);
            ADD_BYTE("ethernet-encapsulation", 36);
            ADD_BYTE("default-tcp-ttl", 37);
            ADD_INT32("tcp-keepalive", 38);
            ADD_BYTE("keepalive-garbage", 39);
            ADD_STR("nis-domain", 40);
            ADD_IPS("nis-servers", 41);
            ADD_IPS("ntp-servers", 42);
            // 43 == vendor specific, we don't use
            ADD_IPS("nbns-servers", 44);
            ADD_IPS("nbdd-servers", 45);
            ADD_BYTE("netbios-nodetype", 46);
            ADD_STR("netbios-scope", 47);
            ADD_IPS("x-font-servers", 48);
            ADD_IPS("x-dm-servers", 49);
            // 50 == client requesting ip - we ignore
            ADD_INT32("lease-time", 51);

            // server-identifier ( 54 ) - and default siaddr
            if (strcmp(pname, "server-identifier") == 0) {
                ADD_IP("server-identifier", 54);
                if (siaddr == 0) siaddr = getip(pvalue);
                continue;
            }

	    // next-server ( siaddr )
	    if (strcmp(pname, "next-server") == 0) {
	        siaddr = getip(pvalue);
	    }

            // filename ( file )
            if (strcmp(pname, "filename") == 0) {
                memset(file, 0, sizeof(file));
                strcpy(file, pvalue);
            }

            // pool-start ( not-in-return-packet )
            if (strcmp(pname, "pool-start") == 0) {
                poolstart = getip(pvalue);
                continue;
            }

            // pool-end ( not-in-return-packet )
            if (strcmp(pname, "pool-end") == 0) {
                poolend = getip(pvalue);
                continue;
            }

            // address ( yiaddr )
            if (strcmp(pname, "address") == 0) {

                // set yiaddr
                yiaddr = getip(pvalue);

                // This is marked so we don't have to allocate an
                // IP from the dynamic pool
                fixedip = 1;
                continue;
            }
        }

        // Fixed lease
        if (strstr(line, "{")) {
            // Parse the mac address
            sscanf(line, "%s %s", pvalue, pname);

	    // Upper case it for comparison
            for (i = 0; i < strlen(pvalue); i++)
                *(pvalue + i) = toupper(*(pvalue + i));

            // Does it match our client? 
            skip_block = 0;
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Comparing chaddr '%s' to config declaration for '%s'", clientmacstr, pvalue);
            #endif
	    // strcmp returns 0, it matches and we want to read the config
	    // values (so don't skip)
	    skip_block = strcmp(clientmacstr, pvalue);
        }

        // End of the fixed block, stop skipping
        if (strstr(line, "}")) {
            skip_block = 0;
        }

    }
    fclose(f);

    #ifdef USE_NSS
    if (!fixedip) {
        char hostname[256];

        if (ether_ntohost(hostname, &clientmac) == 0) {
            struct hostent *e;
           
            if ((e = gethostbyname(hostname)) != NULL) {
                in_addr_t iaddr = *(in_addr_t*)e->h_addr;
   
                // set hostname 
                if (!option_set(12)) {
                    char *c;

                    if ((c = index(hostname, '.')))
                        *c = '\0';

                    *p = 12; p++;
                    p += addstr(p, hostname);
                }

                yiaddr = htonl(iaddr);
                fixedip = 1;
            }
        }
    }
    #endif

    // End of options
    *p = 0xFF;

    // If we didn't have a fixed IP allocation, get an address
    // from the pool to set yiaddr.
    if (!fixedip) {
        yiaddr = get_pool_address();
        if (yiaddr == 0) {
            #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "Exhausted address pool - cannot give address to %02X:%02X:%02X:%02X:%02X:%02X",
                clientmac.ether_addr_octet[0], clientmac.ether_addr_octet[1],
                clientmac.ether_addr_octet[2], clientmac.ether_addr_octet[3],
                clientmac.ether_addr_octet[4], clientmac.ether_addr_octet[5]);
            #endif
            return 0; // No addresses available, bail
        }
    }

    return 1;

}

// Bundles everything up into the packet for sending
// and returns the length of the packet
int serialise_reply() {

    // Clear the packet
    memset(packet, 0, sizeof(packet));
    unsigned char* p = packet;
    
    // Bundle everything in for the response
    INT8_TO_BUF(op, p);
    INT8_TO_BUF(htype, p);
    INT8_TO_BUF(hlen, p);
    INT8_TO_BUF(hops, p);
    INT32_TO_BUF(xid, p);
    INT16_TO_BUF(secs, p);
    INT16_TO_BUF(flags, p);
    INT32_TO_BUF(ciaddr,p);
    INT32_TO_BUF(yiaddr,p);
    INT32_TO_BUF(siaddr,p);
    INT32_TO_BUF(giaddr,p);
    memcpy(p, chaddr, 16);
    p += 16;
    memset(p, 0, 64); // sname
    p += 64; 
    memcpy(p, file, 128); // file
    p += 128;
    INT32_TO_BUF(0x63825363, p); // magic cookie
    memcpy(p, options, sizeof(options));

    // Determine the packet length by counting backwards until
    // we find an 0xFF, terminating the options field
    int i;
    for (i = sizeof(packet); i > 235; i--)
        if (packet[i] == 0xFF)
            return i+1; // Include that extra terminator
  
    // No terminating char - something has gone wrong
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "Couldn't find terminating byte in packet, abandoning");
    #endif
    return 0;

}

// Read the incoming packet and set some
// variables for client mac address, packet
// type, etc.
int parse_packet() {

    unsigned char* p = packet;
    BUF_TO_INT8(op, p);
    BUF_TO_INT8(htype, p);
    BUF_TO_INT8(hlen, p);
    BUF_TO_INT8(hops, p);
    BUF_TO_INT32(xid, p);
    BUF_TO_INT16(secs, p);
    BUF_TO_INT16(flags, p);
    BUF_TO_INT32(ciaddr, p);
    BUF_TO_INT32(yiaddr, p);
    BUF_TO_INT32(siaddr, p);
    BUF_TO_INT32(giaddr, p);
    memcpy(chaddr, p, 16);
    p += 16;
    memcpy(sname, p, 64);
    p += 64;
    memcpy(file, p, 128);
    p += 128;
    // Skip the magic cookie
    p += 4;
    memcpy(options, p, 308);

    // Copy the client hardware address to our clientmac
    // field
    memcpy(clientmac.ether_addr_octet, chaddr, 6);

    // We expect tag 53 (DHCP Message type) to be the
    // first option.
    if (options[0] == (unsigned char) 53) {
        unsigned char* mtype = options;
        mtype += 2;
        BUF_TO_INT8(dhcp_message_type, mtype);
    }
    else {
        // Oops - it's not the first option
        #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "DHCP Message Type not first option, ignoring bad packet.");
        #endif
        return 0;
    }
    return 1;
}

// Sends a UDP packet to the broadcast address on the
// bootpc port
int udp_send(char *data, int len)
{
    int                 n;
    int                 sock;
    int                 broadcast = 1;
    struct sockaddr_in  serv_addr;
    struct sockaddr_in  cli_addr;

    memset((char *)&cli_addr, 0, sizeof(cli_addr));
    memset((char *)&serv_addr, 0, sizeof(serv_addr));

    if (inet_aton(BROADCAST_ADDR, &serv_addr.sin_addr) == 0) {
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((u_short) BOOTPC);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == - 1) {
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast,sizeof broadcast) == -1)
        return -1;

    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons((u_short) 1234);
    if (*bindaddress == '\0')
        cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        cli_addr.sin_addr.s_addr = inet_addr(bindaddress);

    bind(sock,(struct sockaddr *)&cli_addr,sizeof(cli_addr));
    n = sendto(sock, data, len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    close(sock);
    return n;
}


// Parses the packet data and crafts the response
int get_response() {
    if (!parse_packet()) return 0;
    if (!construct_response()) return 0;
    return serialise_reply();
}




int main(int argc, char** argv) {

    // Make sure we have our interface set
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [<bind address>]\n", argv[0]);
	exit(1);
    }
    strcpy(iface, argv[1]);
    *bindaddress = '\0';
    if (argc == 3) strcpy(bindaddress, argv[2]);
    sprintf(configfile, CONFIG, iface);
    sprintf(leasesfile, LEASES, iface);

    // Die if idle for a bit
    alarm(10);

    // Get client address and reply for UDP response
    populate_address();

    // Receive UDP data
    recv_data();

    // Parse the packet and generate a response
    int packetlen = get_response();
    if (!packetlen) return 0;

    #ifdef PACKETDUMP
        FILE* f = fopen(OUTBOUND_PACKET, "wb");
        fwrite(packet, sizeof(unsigned char), packetlen, f);
        fclose(f);
    #endif

    #ifdef ONELOG
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_NOTICE), "%s chaddr=%s yiaddr=%s via=%s", (dhcp_message_type == DHCPDISCOVER ? "DHCPOFFER" : "DHCPACK"), clientmacstr, inet_ntoa(htonl(yiaddr)), (*bindaddress == '\0' ? "255.255.255.255" : bindaddress));
    #endif

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Sending DHCP response packet of length %d to %s:%d", packetlen,BROADCAST_ADDR, BOOTPC);
    #endif

    // Send the response
    if (-1 == udp_send(packet, packetlen)) {
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "Failed sending UDP packet to %s:%d", BROADCAST_ADDR, BOOTPC);
    #endif
    }

    // Success!
    exit(0);

}

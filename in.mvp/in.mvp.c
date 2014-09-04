/*  
 *  MediaMVP service redirector
 *
 *  Used for crossing subnets
 *
 *  Author unknown. Modified by R. Rawson-Tetley, 01/09/2008
 *  to use inetd, stripped Win32 crap and outputs to syslogger.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#ifdef LOGGING
#include <syslog.h>
#endif

#ifdef ONELOG
#include <syslog.h>
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>

/* Some handy (de-) serialisation macros */
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

#define BUF_TO_INT16(dest,src) \
(dest) = (((unsigned char)(src)[0] << 8) | (unsigned char)(src)[1]); \
(src) += 2;

#define BUF_TO_INT32(dest,src) \
(dest) = ( ((unsigned char)(src)[0] << 24) | ((unsigned char)(src)[1] << 16) |((unsigned char)(src)[2] << 8) | (unsigned char)(src)[3]); \
(src) += 4;

typedef struct {
    uint32_t  sequence;
    uint32_t  id1;
    uint32_t  id2;
    uint8_t   mac[6];
    uint8_t   pad[2];
    uint32_t  client_addr;
    uint16_t  client_port;
    uint8_t   pad2[2];
    uint32_t  guiserv_addr;
    uint16_t  guiserv_port;
    uint8_t   pad3[2];
    uint32_t  conserv_addr;
    uint16_t  conserv_port;
    uint8_t   pad4[6];
    uint32_t  serv_addr;
    uint16_t  serv_port;
} udpprot_t;

#define STDIN 0
#define STDOUT 1
static int listenport = 16881;
static int c_gui_port = 5906;
static int c_stream_port = 6337;
static uint32_t c_vdr_host = 0x7f000001;

static struct sockaddr_in from;
static int fromlen;

static int udp_send(char *data, int len, const char *addr, int port);
static void parse_udp(udpprot_t *prot,unsigned char *buf, int len);
static void serialise_udp(udpprot_t *prot, unsigned char *buf, int len);

static char data[2000];
static char mac_address[6];

// Gets the MAC address for the local interface, ipaddr is the
// address passed on the command line.
char* get_mac_address(char* ipaddr) {

    int s;
    struct ifreq *ifr, *ifend;
    struct ifreq ifreq;
    struct ifconf ifc;
    int is_mac=-1;
    #define MAX_IFS 20
    struct ifreq ifs[MAX_IFS];    
   
    // Opens a datagram socket so we can read the
    // mac address and a few other bits
    // =================================================
    s = socket(AF_INET, SOCK_DGRAM, 0);

    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
        #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "ioctl(SIOCGIFCONF): %m\n");
        #endif
        return 0;
    }
    
    ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
        if (ifr->ifr_addr.sa_family == AF_INET) {
            strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));
            if (ioctl (s, SIOCGIFADDR , &ifreq) < 0) {
                #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "SIOCGIFADDR (%s): %m\n", ifreq.ifr_name);
                #endif
                break;
            }
            if (strcmp(ipaddr,inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr)) ){
                continue;
            }
            if (ioctl (s, SIOCGIFHWADDR, &ifreq) < 0) {
                #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "SIOCGIFHWADDR(%s): %m\n", ifreq.ifr_name);
                #endif
                break;
            }
            #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "ip: %s, hw: %s = %02x:%02x:%02x:%02x:%02x:%02x",
                   inet_ntoa(((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr),
                   ifreq.ifr_name,
                   (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[0],
                   (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[1],
                   (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[2],
                   (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[3],
                   (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[4],
                   (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[5]);
            #endif
            memcpy(mac_address,ifreq.ifr_hwaddr.sa_data,6);
            is_mac=1;
            break;
        }
    }
    close(s);
    if (is_mac==-1) {
        #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "Network interface not found");
        #endif
        return NULL;
    }
    return mac_address;
}

char* get_empty_mac() {
    memset(mac_address, 0, 6);
    #ifdef LOGGING
    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "ip: 0.0.0.0, hw: unknown = 00:00:00:00:00:00");
    #endif
    return mac_address;
}


int
main(int argc, char **argv) {
    int len, port;
    udpprot_t      prot;
    int            destport;
    char          *desthost;
    uint32_t       desthostip;
    struct in_addr in;

    if (argc != 2) {
        fprintf(stderr, "usage: %s hostname\n",argv[0]);
        return 0;
    }

    // Ports and host
    port = listenport;
    c_gui_port = 5906;
    c_stream_port = 6337;
    c_vdr_host = htonl(inet_addr(argv[1]));

    // Get the MAC address
    //get_empty_mac();
    get_mac_address(argv[1]);

    // Get the socket from address
    fromlen = sizeof(from);
    memset(&from, 0, sizeof(from));
    getpeername(STDIN, (struct sockaddr *) &from, &fromlen);

    // Get the packet
    len = recvfrom(STDIN, data, sizeof(data), MSG_WAITALL, &from, &fromlen);

    // Ignore packets of the wrong size
    if ( len == 52 ) {
        parse_udp(&prot, (unsigned char*)data, len);

        if ( prot.id1 != 0xbabe || prot.id2 != 0xfafe ) {
            #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "id1 = %04x id2=%04x\n",prot.id1,prot.id2);
            #endif
            return 1;
        }

        // Make our reply packet
        prot.id1 = 0xfafe;
        prot.id2 = 0xbabe;
        memset(&prot.mac,0,8);
        memcpy(prot.mac, mac_address, 6);
        destport = prot.client_port;
        prot.client_port = 2048;
        prot.guiserv_addr = c_vdr_host;
        prot.guiserv_port = c_gui_port;
        prot.conserv_addr = c_vdr_host;
        prot.conserv_port = c_stream_port;
        prot.serv_addr = c_vdr_host;
        prot.serv_port = 16886;

        // Package the response
        serialise_udp(&prot, (unsigned char*)data, 52);

        // Reply
        desthostip = ntohl(prot.client_addr);
        memcpy(&in,&desthostip,4);
        desthost = inet_ntoa(in);
        #ifdef ONELOG
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_NOTICE), "MVPOUT dest=%s, tftp=%s", inet_ntoa(from.sin_addr), argv[1]);
        #endif
        udp_send(data,52, desthost, destport);
    }
    else {
        #ifdef ONELOG
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "MVPERR size=%d, host=%s", len, inet_ntoa(from.sin_addr));
        #endif
    }

    return 0;
}

static int udp_send(char *data, int len, const char *addr, int port)
{
    int                 n;
    int                 sock;
    struct sockaddr_in  serv_addr;
    struct sockaddr_in  cli_addr;

    memset((char *)&cli_addr, 0, sizeof(cli_addr));
    memset((char *)&serv_addr, 0, sizeof(serv_addr));

    if (inet_aton(addr, &serv_addr.sin_addr) == 0) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == - 1) {
        return -1;
    }
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons((u_short)1234);
    cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sock,(struct sockaddr *)&cli_addr,sizeof(cli_addr));


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons((u_short)port);

    n = sendto(sock, data, len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    close(sock);

    return n;

}

static void parse_udp(udpprot_t *prot,unsigned char *buf, int len)
{
    unsigned char  *ptr = buf;

    BUF_TO_INT32(prot->sequence,ptr);
    BUF_TO_INT16(prot->id1,ptr);
    BUF_TO_INT16(prot->id2,ptr);
    memcpy(&prot->mac,ptr,6);
    ptr += 6;
    ptr += 2;  /* Skip pad */
    BUF_TO_INT32(prot->client_addr,ptr);
    BUF_TO_INT16(prot->client_port,ptr);
    ptr += 2;  /* Skip pad */
    BUF_TO_INT32(prot->guiserv_addr,ptr);
    BUF_TO_INT16(prot->guiserv_port,ptr);
    ptr += 2;  /* Skip pad */
    BUF_TO_INT32(prot->conserv_addr,ptr);
    BUF_TO_INT16(prot->conserv_port,ptr);
    ptr += 6;  /* Skip pad */
    BUF_TO_INT32(prot->serv_addr,ptr);
    BUF_TO_INT16(prot->serv_port,ptr);
}

static void serialise_udp(udpprot_t *prot, unsigned char *buf, int len)
{
    unsigned char *ptr = buf;
    memset(buf,0,len);

    INT32_TO_BUF(prot->sequence,ptr);
    INT16_TO_BUF(prot->id1,ptr);
    INT16_TO_BUF(prot->id2,ptr);

    memcpy(ptr,prot->mac,6);
    ptr += 6;
    ptr += 2;  /* Skip pad */
    INT32_TO_BUF(prot->client_addr,ptr);
    INT16_TO_BUF(prot->client_port,ptr);
    ptr += 2;  /* Skip pad */
    INT32_TO_BUF(prot->guiserv_addr,ptr);
    INT16_TO_BUF(prot->guiserv_port,ptr);
    ptr += 2;  /* Skip pad */
    INT32_TO_BUF(prot->conserv_addr,ptr);
    INT16_TO_BUF(prot->conserv_port,ptr);
    ptr += 6;  /* Skip pad */
    INT32_TO_BUF(prot->serv_addr,ptr);
    INT16_TO_BUF(prot->serv_port,ptr);
}


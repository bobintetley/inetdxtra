/*
 * in.jabberd - a miniscule jabber server that runs
 * through inetd.
 *
 * Supports nothing but chat.
 * Supports plaintext password and digest authentication
 *
 * If you use a vCard with an image, it will blow it up
 * due to small buffer sizes, this isn't a worry though
 * since obviously only the logging in process will
 * die and nobody else's process.
 *
 * Presence information is inferred from the files in its
 * tmp folder (one is created for each logged in user and
 * removed when a user quits) and these files are used for
 * IPC between multiple in.jabberd processes.
 * flock(LOCK_EX) is used to synchronize file access.
 *
 * Author: Robin Rawson-Tetley
 * Licence: GPLv2
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef LOGGING
    #include <syslog.h>
#endif
#ifdef ONELOG
    #include <syslog.h>
#endif
#include <fcntl.h>
#include <dirent.h>
#include "sha1.h"

#define VERSION "201409"
#define PROGNAME "in.jabberd"
#define WORKING_FOLDER "/tmp"
#define USER_LIST "/etc/in.jabberd.conf"

#define B_SIZE 16384
#define PATH_SIZE 255
#define STDIN 0

// Input/output buffers
char in[B_SIZE];
char out[B_SIZE];
char body[B_SIZE];
char message[B_SIZE];
char messages[B_SIZE];

char iqid[64];
char streamid[64];
char servername[100];
char username[100];
char digest[100];
char password[100];
char sha[100];
char resource[100];
char to[100];
char from[100];
char userandserver[200];
char userandresource[200];
char processname[200];

// Extracts the xml attribute from xml and stores it in buffer
int get_attribute(char* xml, char* attribute, char* buffer) {
    
    // Get to the start of the attribute
    char* as = strstr(xml, attribute);
    if (!as) return 0;

    // Read the attribute
    char* start = NULL;
    int numchars = 0;
    int i = 0;
    for (i = 0; i < strlen(as); i++) {

        if (start) numchars++;

        if (*(as + i) == '\'' || *(as + i) == '"')
            if (!start)
                start = (as + i + 1);
            else
                break;
    }
        
    // Store the result in the buffer
    strncpy(buffer, start, numchars);
    *(buffer + numchars - 1) = '\0';
    //#ifdef LOGGING
    //    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Parsed XML attribute %s = '%s'", attribute, buffer);
    //#endif
    return 1;
}

// Extracts the contents of the xml tag given and stores it in the buffer
int get_tag(char* xml, char* tag, char* buffer) {
    char tagopen[255];
    char tagclose[255];
    char inone[255];
    snprintf(tagopen, 255, "<%s", tag);
    snprintf(tagclose, 255, "</%s>", tag);
    snprintf(inone, 255, "<%s/>", tag);
    // If the tag is present, but has no content, stop now
    if (strstr(xml, inone)) return 1;
    // Get to the start of the tag
    char* as = strstr(xml, tagopen);
    if (!as) return 0;
    char* ap = strstr(as, ">") + sizeof(char);
    if (!ap) return 0;
    // Find the end
    int i = 0;
    while ( *(ap + (sizeof(char) * i)) != '<' && *(ap + (sizeof(char) * i)) != '\0') i++;
    // Store the result in the buffer
    strncpy(buffer, ap, i);
    *(buffer + i) = '\0';
    return 1;
}

// Gets a handle to a user's buffer file
FILE* get_buffer(char* user, char* mode) {
    char fname[PATH_SIZE];
    sprintf(fname, "%s/in.jabberd_%s", WORKING_FOLDER, user);
    FILE* f = fopen(fname, mode);
    flock(f, LOCK_EX);
    return f;
}

// Returns the user portion of user@server type name
// - does it by switching the @ for the end of the 
// string and returning, so it does change the original
// string.
char* get_user(char* user) {
    int i;
    for (i = 0; i < strlen(user); i++) {
        if (*(user+i) == '@') {
            *(user+i) = '\0';
            break;
        }
    }
    return user;
}

// Sends a message to the user specified. We expect there
// to be a single %s token in the message that identifies
// the user, so we can substitute it with our fprintf here
void send_message(char* user, char* message) {
    
    // Make sure we don't have a server bit
    char uname[100];
    strcpy(uname, user);
    get_user(uname);

    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "(sent message to %s)", uname);
    #endif

    // Get a handle to the user's buffer
    FILE* f = get_buffer(uname, "a");
    if (!f) return;

    // If there's a placeholder in the message, substitute the
    // username.
    if (strstr(message, "'%"))
        fprintf(f, message, uname);
    else
        fprintf(f, message);

    fflush(f);
    fclose(f);
}

// Calculates a SHA-1 digest of a given string and returns
// a pointer to the "sha" buffer.
char* sha1(char* message) {
    SHA1Context s;
    uint8_t result[20];

    // Calculate the hash
    SHA1Reset(&s);
    SHA1Input(&s, message, strlen(message));
    SHA1Result(&s, result);

    // Load the readable hash into a string
    sprintf(sha, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7], result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15], result[16], result[17], result[18], result[19]);

    // Lower case the hash string
    int i = 0;
    for (i = 0; i < strlen(sha); i++) {
        *(sha + i) = tolower(*(sha + i));
    }

    return sha;
}

// Sends a message to all logged in users but us
void send_message_all(char* message) {
    DIR* d;
    struct dirent *ds;
    d = opendir(WORKING_FOLDER);
    while ((ds = readdir(d)) != NULL) {
        if (strstr(ds->d_name, "in.jabberd")) {
            if (!strstr(ds->d_name, username)) {
                char* thisuser = strstr(ds->d_name, "_") + sizeof(char);
                char uname[100];
                sprintf(uname, "%s@%s", thisuser, servername);
                send_message(uname, message);
            }
        }
    }
    closedir(d);
}

// Clears/creates a user's buffer file
void create_buffer(char* user) {
    FILE* f = get_buffer(user, "w");
    fclose(f);
}

void delete_buffer(char* user) {
    // Tell other users we're offline
    sprintf(message, "<presence type='unavailable' from='%s' to='%%s'></presence>", userandresource);
    send_message_all(message);
    // Delete our buffer
    char fname[PATH_SIZE];
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "deleting buffer file: %s/in.jabberd_%s", WORKING_FOLDER, user);
    #endif
    sprintf(fname, "%s/in.jabberd_%s", WORKING_FOLDER, user);
    remove(fname);
}

// Reads the messages waiting for our user and
// clears the buffer. If no messages are waiting,
// NULL is returned.
char* recv_messages() {
    FILE* f = get_buffer(username, "r");
    if (!f)
        return NULL;
    int bytesread = fread(messages, 1, sizeof(messages), f);
    if (bytesread < 5) {
        fclose(f);
        return NULL;
    }
    *(messages + bytesread) = '\0';
    fclose(f);
    create_buffer(username);
    return messages;
}

// Returns true if a user is online
int user_online(char* user) {
    FILE* f = get_buffer(user, "r");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

// authenticates a user, finds the user given in the
// config and depending on whether digest or password are
// non-NULL, checks the digest/password for that user and
// returns true if authentication succeeds.
int authenticate(char* user, char* digest, char* pass) {
    char line[255];
    char uname[50];
    char upass[50];
    char idpass[100];
    FILE* f = fopen(USER_LIST, "r");
    while (!feof(f)) {
        fgets(line, 255, f);
        sscanf(line, "%s : %s", uname, upass);
        if (strcmp(uname, user) == 0) {
            
            // Got the right user, authenticate
            #ifdef LOGGING
                 syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Found username '%s'", uname, digest);
            #endif

            // Calculate the hash of their password, prefixed with the id of
            // the stream 
            sprintf(idpass, "%s%s", streamid, upass);
            sha1(idpass);

            // Digest authentication
            if (digest != NULL) {
                #ifdef LOGGING
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Hash given: '%s', Server calculated hash for password: '%s', Hash calculated from: '%s'", digest, sha, idpass);
                #endif
                if (strcmp(digest, sha) == 0) 
                    return 1;
                else
                    return 0;
            }
            // Plaintext password authentication
            else {
                #ifdef LOGGING
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Password given: '%s', Password required: '%s'", pass, upass);
                #endif
                if (strcmp(pass, upass) == 0)
                    return 1;
                else
                    return 0;
            }
        }
    }
    fclose(f);
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Couldn't find a user named %s", user);
    #endif
    return 0;
}

// Returns true if a user is valid
int user_is_valid(char* user) {
    char line[255];
    char uname[50];
    char udig[50];
    FILE* f = fopen(USER_LIST, "r");
    while (!feof(f)) {
        fgets(line, 255, f);
        sscanf(line, "%s = %s", uname, udig);
        if (strcmp(uname, user) == 0) {
            #ifdef LOGGING
                 syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Username '%s' is valid.", uname);
            #endif
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Username '%s' is not valid.", uname);
    #endif
    return 0;
}

// Parses the message and sends a response
int parse_message(char* out, char** argv) {

    int has_iqid = get_attribute(in, "id", iqid);
    int has_username = get_tag(in, "username", username);
    int has_to = get_attribute(in, "to", to);
    int has_from = get_attribute(in, "from", from);
    int has_digest = get_tag(in, "digest", digest);
    int has_password = get_tag(in, "password", password);
    int has_resource = get_tag(in, "resource", resource);
    int has_body = get_tag(in, "body", body);

    // Clear output buffer before we start
    *out = '\0';

    // Ping
    if (strstr(in, "xmpp:ping")) {
        sprintf(out, "<iq type='result' id='%s' from='%s' to='%s' />", iqid, servername, userandresource);
        return 1;
    }

    // Handshake from client
    if (strstr(in, "<stream:stream")) {
        strcpy(servername, to);
        sprintf(out, "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' id='%s' xmlns='jabber:client' from='%s'>", streamid, servername);
        return 1;
    }

    // Login, step 1, client requests authentication
    // methods. We can handle plaintext password or sha-1 digest.
    if (strstr(in, "jabber:iq:auth") && has_username && !has_password && !has_digest) {
        sprintf(out, "<iq type='result' id='%s'><query xmlns='jabber:iq:auth'><username>%s</username><digest/><password/><resource/></query></iq>", iqid, username);
        return 1;
    }

    // Login, step 2
    if (strstr(in, "jabber:iq:auth") && (has_password || has_digest)) {

        // Do we have a password or a digest to try?
        int authenticated = 0;
        if (has_digest)
            authenticated = authenticate(username, digest, NULL);
        else
            authenticated = authenticate(username, NULL, password);

        // Cut the connection if authentication failed
        if (!authenticated) {
            #ifdef ONELOG
                syslog(LOG_MAKEPRI(LOG_AUTH, LOG_ERR), "DENIED %s", username);
            #endif
            return 0;
        }

        // We're good, they passed
        sprintf(userandresource, "%s@%s/%s", username, servername, resource);
        sprintf(userandserver, "%s@%s", username, servername);
        sprintf(out, "<iq type='result' id='%s' />", iqid);
        create_buffer(username);

        // Update our command line for ps so we can see who logged in
        #ifdef UPDATEPS
        int arg0sz = strlen(argv[0]);
        sprintf(processname, "in.jabberd: %s", username);
        strcpy(argv[0], processname); // deliberate overflow - we don't need env
        #endif
        #ifdef ONELOG
            syslog(LOG_MAKEPRI(LOG_AUTH, LOG_NOTICE), "LOGIN %s", userandresource);
        #endif
        return 1;
    }

    // Discovery, step 1
    if (strstr(in, "disco#items")) {
        sprintf(out, "<iq type='result' id='%s' to='%s' from='%s'><query xmlns='http://jabber.org/protocol/disco#items#' /></iq>", iqid, userandresource, servername);
        return 1;
    }

    // Discovery, step 2 - we support item discovery, version and ping
    if (strstr(in, "disco#info")) {
        sprintf(out, "<iq type='result' id='%s' to='%s' from='%s'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='services' type='jabber' name='%s %s' /><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='urn:xmpp:ping'/><feature var='jabber:iq:version'/></query></iq>", iqid, userandresource, servername, PROGNAME, VERSION);
        return 1;
    }

    // Buddy roster - built from our list of users in the config file and who's online
    if (strstr(in, "jabber:iq:roster")) {
        char presence[B_SIZE];
        char line[255];
        char uname[50];
        char udig[50];
        char thisitem[200];
        char thispresence[200];
        *presence = '\0';
        int i = 0;
        sprintf(out, "<iq type='result' id='%s' from='%s'><query xmlns='jabber:iq:roster'>", iqid, userandresource);
        FILE* f = fopen(USER_LIST, "r");
        // Loop through the list of users we have for the
        // server and see if they're online. Use it to generate the
        // presence packets
        while (!feof(f)) {
            fgets(line, 255, f);
            sscanf(line, "%s : %s", uname, udig);
            
            // Don't do anything if it's us or a comment
            if (strstr(uname, username) || strstr(uname, "#")) continue;

            // Strip line break
            for (i = 0; i < strlen(uname); i++) {
                if (*(uname + i) == '\n') {
                    *(uname + i) = '\0';
                    break;
                }
            }

            // Is the user online?
            char* availability = "available";
            if (!user_online(uname))
                availability = "unavailable";

            // Build the current roster item and presence packet
            sprintf(thisitem, "<item jid='%s@%s' name='%s' subscription='both'><group>%s</group></item>", uname, servername, uname, servername);
            sprintf(thispresence, "<presence type='%s' from='%s@%s' to='%s'></presence>", availability, uname, servername, userandresource);

            // Build the message and collection of presence packets
            strcat(out, thisitem);
            strcat(presence, thispresence);
        }
        fclose(f);

        // Finish off the query and add presence tags
        strcat(out, "</query></iq>\n");
        strcat(out, presence);
        return 1;
    }

    // Privacy list
    if (strstr(in, "jabber:iq:privacy")) {
        sprintf(out, "<iq type='result' id='%s' to='%s' from='%s'><query xmlns='jabber:iq:privacy' /></iq>", iqid, userandresource, servername);
        return 1;
    }

    // Presence update - when the client sends us one, we just assume
    // they're available, we infer unavailability when we lose the connection
    if (strstr(in, "<presence")) {
        // Notify all users that we're available
        // The %%s tag means it becomes %s in the called function, where the username
        // can be replaced.
        sprintf(message, "<presence type='available' from='%s' to='%%s'></presence>", userandresource);
        send_message_all(message);
        // Send back an empty tag so the client has some kind of acknowledgement
        sprintf(out, "<presence />");
        return 1;
    }

    // vCard - if a client send us one, acknowledge it, but do nothing
    if (strstr(in, "vcard") || strstr(in, "vCard")) {
        sprintf(out, "<iq type='result' id='%s' from='%s'><vCard xmlns='vcard-temp'/></iq>", iqid, userandresource);
        return 1;
    }

    // Chat message
    if (strstr(in, "<message")) {

        // Composing notification
        if (strstr(in, "<composing") && !has_body) {
            sprintf(message, "<message from='%s' to='%%s'><x xmlns='jabber:x:event'><composing/><id>%s</id></x></message>", userandresource, iqid);
            send_message(get_user(to), message);
            return 1;
        }

        // Empty messages reset events
        if (!has_body || strlen(body) == 0 || strcmp(body, " ") == 0) {
            sprintf(message, "<message from='%s' to='%%s'><x xmlns='jabber:x:event'><id>%s</id></x></message>", userandresource, iqid);
            send_message(get_user(to), message);
            return 1;
        }

        // Relay the message to its recipient and subscribe 
        // for composing events
        sprintf(message, "<message type='chat' id='%s' to='%%s' from='%s'><body>%s</body><x xmlns='jabber:x:event'><composing/></x><html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'>%s</body></html></message>", iqid, userandresource, body, body);
        send_message(get_user(to), message);
        return 1;
    }

    // Close connection
    if (strstr(in, "</stream:stream")) {
        #ifdef LOGGING
            syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Stream closed by client.");
        #endif
        #ifdef ONELOG
            syslog(LOG_MAKEPRI(LOG_AUTH, LOG_NOTICE), "LOGOUT %s", userandresource);
        #endif
        delete_buffer(username);
        return 0;
    }

    // XML declaration before handshake - ignore
    if (strstr(in, "<?xml")) {
        return 1;
    }

    // Unknown message - do nothing and log it
    #ifdef LOGGING
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "Didn't understand client message:\n%s", in);
    #endif
    return 1;

}

void generate_random_hex(char* str, int len) {
    const char* chars = "abcdef0123456789";
    int max = strlen(chars);
    int i = 0;
    for (; i < len - 2; ++i) {
        str[i] = chars[ rand() % max ];
    }
    str[i] = '\0';
}


int main(int argc, char** argv) {

    // Make stdin use non-blocking IO
    fcntl(STDIN, F_SETFL, fcntl(STDIN, F_GETFL) | O_NONBLOCK);
    #ifdef LOGGING 
        syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "%s %s: started with non-blocking IO", PROGNAME, VERSION);
    #endif

    // Generate our stream id (one stream id per process)
    srand( (unsigned) time( (time_t *) 0));
    generate_random_hex(streamid, 8);
    
    int bytesread = 0;
    *username = '\0';

    while(1) {
        usleep(30000);
        bytesread = fread(in, 1, sizeof(in), stdin);
        if (bytesread > 0) {
            *(in + bytesread) = '\0';

            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "CLIENT (%s): %s", username, in);
            #endif

            if (!parse_message(out, argv)) {
                #ifdef LOGGING
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_ERR), "Parser terminated.");
                #endif

                delete_buffer(username);
                exit(1);
            }
            else {
                #ifdef LOGGING
                    syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "SERVER (%s): %s", username, out);
                #endif

                printf(out);
                fflush(stdout);
            }
        }
        if (feof(stdin)) {
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "Connection closed.");
            #endif

            delete_buffer(username);
            exit(0);
        }

        // Poll for new messages to send us
        char* m = recv_messages();
        if (m) {
            #ifdef LOGGING
                syslog(LOG_MAKEPRI(LOG_DAEMON, LOG_DEBUG), "SERVER (%s): %s", username, m);
            #endif

            printf(m);
            fflush(stdout);
        }
    }
}



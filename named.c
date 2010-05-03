#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>

#include <event-config.h>
#include <alloca.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/util.h>

#ifdef _EVENT_HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "log.h"
#include "dns.h"
#include "buffer.h"
#include "list.h"

typedef void (*NamedAnswerFunc)(DNSResourceRecord *record);
static void named_query(const char *name, DNSQueryClass qclass, DNSQueryType qtype, NamedAnswerFunc);
static void named_on_request(DNSRequest *req, void *data);

static sqlite3 *named_db = NULL;

static void named_query(const char *name, DNSQueryClass qclass, DNSQueryType qtype, NamedAnswerFunc on_answer)
{
    char *sql;
    LOG_DEBUG("query: %s, class: %d, type: %d", name, qtype, qclass);
    if (qtype != DNSWildcardQueryType && qclass != DNSWildcardQueryClass)
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s' AND qclass = %d AND qtype = %d", name, (int) qclass, (int) qtype);
    else if (qtype == DNSWildcardQueryType)
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s' AND qclass = %d", name, (int) qclass);
    else if (qclass == DNSWildcardQueryClass)
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s' AND qtype = %d", name, (int) qtype);
    else
        sql = sqlite3_mprintf("SELECT name, qtype, qclass, rdata, ttl FROM responses WHERE name = '%s'", name);

    const char *left;
    sqlite3_stmt *stmt;

    int rc = sqlite3_prepare_v2(named_db, sql, -1, &stmt, &left);
    if ((rc == SQLITE_BUSY) || (rc == SQLITE_LOCKED)) {
        LOG_ERROR("the sqlite database seems to be locked or busy");
    } else if (rc != SQLITE_OK) {
        LOG_ERROR("unknown error while preparing sqlite statement: rc = %d", rc);
    }
    sqlite3_reset(stmt);
    while (1) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            // query is done returning results, nothing to see here
            break;
        } else if (rc == SQLITE_OK || rc == SQLITE_ROW) {
            Buffer *rr_data_buf = buffer_new(sqlite3_column_blob(stmt, 3), sqlite3_column_bytes(stmt, 3));
            DNSResourceRecord *record = dnsresourcerecord_new(
                    (const char *)sqlite3_column_text(stmt, 0),
                    sqlite3_column_int(stmt, 1),
                    sqlite3_column_int(stmt, 2),
                    sqlite3_column_int(stmt, 4),
                    rr_data_buf);
            buffer_free(rr_data_buf);
            on_answer(record);
            dnsresourcerecord_free(record);
        } else {
            LOG_ERROR("unknown error in sqlite3_step: rc = %d", rc);
            exit(1);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_free(sql);
}

static void named_on_request(DNSRequest *req, void *data)
{
    LOG_DEBUG("rx request");
    DNSResponse *response = dnsresponse_new(req);
    void on_answer(DNSResourceRecord *record) {
        LOG_DEBUG("answer for name: %s, %d, %s", record->name, (int)record->qtype, (char *)buffer_data(record->data));
        list_append(response->message->answers, dnsresourcerecord_copy(record));
    }
    void on_question(List *a_list, void *ctx, void *item, bool *keep_going) {
        DNSQuestion *question = (DNSQuestion *)item;
        named_query(question->name, question->qclass, question->qtype, on_answer);
    }
    list_iterate(response->message->questions, on_question, NULL);
    dnsresponse_finish(response);
    LOG_DEBUG("responded");
}

static void drop_privileges(const char *pw_name)
{
    struct passwd *pwd;
    if (getuid() == 0 && strlen(pw_name)) {
        pwd = getpwnam(pw_name);
        setuid(pwd->pw_uid);
        LOG_INFO("dropped uid to %d", pwd->pw_uid);
        if (getgid() == 0 && pwd->pw_gid)  {
            setgid(pwd->pw_gid);
            LOG_INFO("dropped gid to %d", pwd->pw_gid);
        }
    }
}

int main(int argc, char **argv)
{
    LOG_INFO("startup")
    struct event_base *event_base = NULL;
    struct sockaddr_in udp_addr;
    struct sockaddr_in tcp_addr;
    int rc;
    int udp_sock;
    int tcp_sock;
    int port = 10053;

    char *priv_user = calloc(1024, sizeof(char));

    int ch = -1;
    while ((ch = getopt(argc, argv, "dp:u:")) != -1) {
        switch (ch) {
        case 'd':
            log_level = LogDebugLevel;
            break;
        case 'p':
            if ((1 <= atoi(optarg)) && (atoi(optarg) < (1 << 16)))
                port = atoi(optarg);
            break;
        case 'u':
            strcpy(priv_user, optarg);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    rc = sqlite3_open(argv[0], &named_db);
    if (rc) {
        LOG_ERROR("Can't open database: %s", sqlite3_errmsg(named_db));
        sqlite3_close(named_db);
        exit(1);
    }
    event_base = event_base_new();

    udp_sock = socket(PF_INET, SOCK_DGRAM, 0);
    tcp_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (udp_sock < 0) {
        perror("socket");
        exit(1);
    }
    if (tcp_sock < 0) {
        perror("socket");
        exit(1);
    }
    evutil_make_socket_nonblocking(udp_sock);
    evutil_make_socket_nonblocking(tcp_sock);
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(port);
    udp_addr.sin_addr.s_addr = INADDR_ANY;
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons(port);
    tcp_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_sock, (struct sockaddr*) &udp_addr, sizeof(udp_addr)) < 0) {
        perror("bind udp");
        exit(1);
    }
    if (bind(tcp_sock, (struct sockaddr*) &tcp_addr, sizeof(tcp_addr)) < 0) {
        perror("bind tcp");
        exit(1);
    }

    if (listen(tcp_sock, 10) < 0) {
        perror("failed to listen");
        exit(1);
    }
    /* bind(2) is done, it's time to drop privileges */
    drop_privileges(priv_user);
    free(priv_user);
    DNSPort *tcp_port = dnsport_new(event_base, tcp_sock, true, named_on_request, NULL);
    DNSPort *udp_port = dnsport_new(event_base, udp_sock, false, named_on_request, NULL);
    event_base_dispatch(event_base);
    dnsport_free(tcp_port);
    dnsport_free(udp_port);

    sqlite3_close(named_db);
    LOG_INFO("done")
    return 0;
}


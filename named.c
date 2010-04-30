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
#include <event2/dns.h>
#include <event2/dns_struct.h>
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

static const int NAMED_TTL = 300;
static sqlite3 *named_db = NULL;
static const char *NAMED_COL_DATA = "data";
static const char *NAMED_COL_TTL = "ttl";
static const char *NAMED_COL_QCLASS = "qclass";
static const char *NAMED_COL_QTYPE = "qtype";
static const char *NAMED_COL_NAME = "name";

static void named_query(const char *name, DNSQueryClass qclass, DNSQueryType qtype, NamedAnswerFunc on_answer)
{
    char *error_msg = NULL;
    char sql[256 + strlen(name)];
    LOG_DEBUG("query: %s, class: %d, type: %d", name, qtype, qclass);

    if (qtype != DNSWildcardQueryType && qclass != DNSWildcardQueryClass)
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s' AND qclass = %d AND qtype = %d", name, (int)qclass, (int)qtype);
    else if (qtype == DNSWildcardQueryType)
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s' AND qclass = %d", name, (int)qclass);
    else if (qclass == DNSWildcardQueryClass)
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s' AND qtype = %d", name, (int)qtype);
    else
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s'", name);

    int query_name_response(void *ctx, int col_count, char **data, char **column_names) {
        const char *response_data = "";
        const char *qname = "";
        DNSQueryClass qclass = DNSInternetQueryClass;
        DNSQueryType qtype = DNSTxtQueryType;
        uint32_t ttl = NAMED_TTL;
        Buffer *buf = NULL;
        for (int i = 0; i < col_count; i++) {
            const char *col = column_names[i];
            const char *val = data[i];
            if (val == NULL)
                continue;
            if (strcmp(col, NAMED_COL_DATA) == 0) {
                buf = buffer_new((uint8_t *)val, strlen(val));
            } else if (strcmp(col, NAMED_COL_TTL) == 0)
                ttl = atoi(val);
            else if (strcmp(col, NAMED_COL_NAME) == 0)
                qname = val;
            else if (strcmp(col, NAMED_COL_QCLASS) == 0)
                qclass = atoi(val);
            else if (strcmp(col, NAMED_COL_QTYPE) == 0)
                qtype = atoi(val);
        }
        DNSResourceRecord *record = dnsresourcerecord_new(qname, qtype, qclass, ttl, buf);
        buffer_free(buf);
        on_answer(record);
        dnsresourcerecord_free(record);
        return 0;
    }

    int rc = sqlite3_exec(named_db, sql, query_name_response, 0, &error_msg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("SQL Error: %s", error_msg);
        sqlite3_free(error_msg);
        exit(1);
    }
}

static void named_on_request(DNSRequest *req, void *data)
{
    uint32_t ttl = 300;
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

static void named_logger(int is_warn, const char *msg)
{
    fprintf(stderr, "%s: %s\n", is_warn ? "WARN" : "INFO", msg);
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

void named_handle_request(DNSRequest *request, void *ctx) {
    LOG_DEBUG("named_handle_request");
}

int main(int argc, char **argv)
{
    LOG_INFO("startup")
    struct event_base *event_base = NULL;
    struct evdns_base *evdns_base = NULL;
    struct sockaddr_in my_addr;
    int rc;
    int sock;
    int port = 10053;

    char *priv_user = calloc(1024, sizeof(char));

    int ch = -1;
    while ((ch = getopt(argc, argv, "dp:u:")) != -1) {
        switch (ch) {
        case 'd':
            log_level = LogDebugLevel;
            break;
        case 'p':
            if (1 <= atoi(optarg) < (1 << 16))
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
    evdns_base = evdns_base_new(event_base, 0);
    evdns_set_log_fn(named_logger);

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }
    evutil_make_socket_nonblocking(sock);
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*) &my_addr, sizeof(my_addr)) < 0) {
        perror("bind");
        exit(1);
    }

    /* bind(2) is done, it's time to drop privileges */
    drop_privileges(priv_user);
    free(priv_user);

    //evdns_add_server_port_with_base(event_base, sock, 0, named_on_evdns_request, NULL);
    DNSPort *udp_port = dnsport_new(event_base, sock, false, named_on_request, NULL);

    event_base_dispatch(event_base);
    sqlite3_close(named_db);
    LOG_INFO("done")
    return 0;
}


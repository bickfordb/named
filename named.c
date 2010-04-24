#include <event-config.h>

#include <sys/types.h>

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

typedef enum {
    TxtQueryType = 16,
    WildcardQueryType = 255
} QueryType;

typedef enum {
    InternetQueryClass = 1,
    WildcardQueryClass = 255
} QueryClass;

typedef void (*AnswerFunc)(const char *name, const char *data, int data_len, int ttl, QueryClass query_class, QueryType query_type);

// Prototypes
static void query_name(const char *name, QueryClass qclass, QueryType qtype, AnswerFunc);
static void evdns_server_callback(struct evdns_server_request *req, void *data);
static void fmt_txt_buf(const uint8_t *in_data, int in_len, uint8_t *out_data, int *out_len, uint8_t max_chunk_size);

// Globals
const int TTL = 300;
sqlite3 *db = NULL;
const char *COL_DATA = "data";
const char *COL_TTL = "ttl";
const char *COL_QCLASS = "qclass";
const char *COL_QTYPE = "qtype";
const char *COL_NAME = "name";

// Macros
#define EV_CHECK(MSG, F) \
{ \
    if (F < 0) { \
        fprintf(stderr, "failed to " MSG); \
        exit(1); \
    } \
}


// Definitions
static void query_name(const char *name, QueryClass qclass, QueryType qtype, AnswerFunc callback) {
  char *error_msg = NULL;
  char sql[256 + strlen(name)];
    fprintf(stderr, "query: %s, class: %d, type: %d\n", name, qtype, qclass);

    if (qtype != WildcardQueryType && qclass != WildcardQueryClass)
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s' AND qclass = %d AND qtype = %d", name, (int)qclass, (int)qtype);
    else if (qtype == WildcardQueryType) 
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s' AND qclass = %d", name, (int)qclass);
    else if (qclass == WildcardQueryClass) 
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s' AND qtype = %d", name, (int)qtype);
    else 
        sprintf(sql, "SELECT name, qtype, qclass, data, ttl FROM responses WHERE name = '%s'", name);

  int query_name_response(void *ctx, int col_count, char **data, char **column_names) {
      const char *response_data = "";
      const char *response_name = "";
      QueryClass response_qclass = InternetQueryClass;
      QueryType response_qtype = 0;
      int response_ttl = TTL;
      int response_data_len = 0;
      for (int i = 0; i < col_count; i++) {
          const char *col = column_names[i];
          const char *val = data[i];
          if (val == NULL)
              continue;
          if (strcmp(col, COL_DATA) == 0) {
              response_data = val;
              response_data_len = strlen(val);  
          } else if (strcmp(col, COL_TTL) == 0) 
              response_ttl = atoi(val);
          else if (strcmp(col, COL_NAME) == 0)
              response_name = val;
          else if (strcmp(col, COL_QCLASS) == 0)
              response_qclass = atoi(val);
          else if (strcmp(col, COL_QTYPE) == 0)
              response_qtype = atoi(val);
      }
      
      if (response_qtype == TxtQueryType) {
           int buf_size = response_data_len + (response_data_len / 255) + 16;
           char *buf = alloca(buf_size);
           fmt_txt_buf(response_data, strlen(response_data), buf, &buf_size, 255);
           response_data = buf;
           response_data_len = buf_size;
      }
      callback(response_name, response_data, response_data_len, response_ttl, response_qclass, response_qtype);
      return 0;
  } 

  int rc = sqlite3_exec(db, sql, query_name_response, 0, &error_msg);
  if (rc != SQLITE_OK) {
      fprintf(stderr, "SQL Error: %s\n", error_msg);
      sqlite3_free(error_msg);
      exit(1);
  }
}


int count_char(uint8_t *buf, int buf_len, uint8_t byte) {
    int num = 0;
    int i =0;
    for (int i = 0; i < buf_len; i++) {
        if (buf[i] == byte) 
            num++; 
    }
    return num;
}

static void fmt_txt_buf(const uint8_t *in_data, int in_len, uint8_t *out_data, int *out_len, uint8_t max_chunk_size) {
    int remaining = in_len;
    int written = 0;
    for (int i = 0; i < in_len && written < *out_len; i++) {
        if ((i % max_chunk_size) == 0) {
            int remaining = in_len - written;
            int chunk_size = max_chunk_size < remaining ? max_chunk_size : remaining;
            out_data[written] = (uint8_t)chunk_size;
            written++;
        }
        out_data[written] = in_data[i];
        written++; 
    }
    *out_len = written;
}  

static void evdns_server_callback(struct evdns_server_request *req, void *data) {
    int ttl = 300;
    fprintf(stderr, "request\n");
    fprintf(stderr, "replying to request\n");

    for (int i = 0; i < req->nquestions; i++) {
        struct evdns_server_question *question = req->questions[i];
        void on_answer(const char *name, const char *data, int data_len, int ttl, QueryClass qclass, QueryType qtype) { 
            fprintf(stderr, "answer name:%s, data:%s\n", name, data);
            EV_CHECK("add reply", evdns_server_request_add_reply(
                req,
                EVDNS_ANSWER_SECTION,
                name,
                (int)qtype,
                (int)qclass,
                ttl,
                data_len, // data len
                0,
                data));
        }
        query_name(question->name, question->dns_question_class, question->type, on_answer);
    }
    EV_CHECK("respond", evdns_server_request_respond(req, 0));
    
    fprintf(stderr, "responded\n");
}

static void logger(int is_warn, const char *msg) {
    fprintf(stderr, "%s: %s\n", is_warn ? "WARN" : "INFO", msg);
}

int main(int argc, char **argv) {

    struct event_base *event_base = NULL;
    struct evdns_base *evdns_base = NULL;

    {
      int rc = sqlite3_open(argv[1], &db);
      if (rc){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
      }
    }
    event_base = event_base_new();
    evdns_base = evdns_base_new(event_base, 0);
    evdns_set_log_fn(logger);

    int sock;
    struct sockaddr_in my_addr;
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }
    evutil_make_socket_nonblocking(sock);
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(10053);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*) &my_addr, sizeof(my_addr)) < 0) {
        perror("bind");
        exit(1);
    }
    evdns_add_server_port_with_base(event_base, sock, 0, evdns_server_callback, NULL);

    event_base_dispatch(event_base);
    sqlite3_close(db);
    return 0;
}

#undef EV_CHECK


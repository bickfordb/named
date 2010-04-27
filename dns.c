#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <event2/util.h>
#include <event2/event_struct.h>
#include <sys/socket.h>

#include "buffer.h"
#include "dns.h"
#include "list.h"
#include "log.h"

#define IS_RETRYABLE(E) ((E) == EINTR || (E) == EAGAIN)
const int DNS_MAX_UDP_PACKET_SIZE = 1500;

struct _DNSMessage { 
    uint16_t id;
    bool is_query : 1;
    int opcode; 
    bool is_recursion_desired : 1;
    bool is_recursion_available : 1;
    List *questions;
    List *answers;
    List *nameservers;
    List *additional;
};


struct _DNSRequest {
   DNSMessage *message; 
   DNSPort *port; 
};



struct _DNSAnswer
{
    char *name;
    DNSQueryClass qclass;
    DNSQueryType qtype;
    int ttl;
    union {
        Buffer *txt;
        uint32_t address4;
        char *cname;
    } data;
};

struct _DNSQuestion
{
    char *name;
    DNSQueryClass qclass;
    DNSQueryType qtype;
};


struct _DNSPort
{ 
    struct event_base *event_base;
    struct event event;
    int socket;
    OnDNSRequest on_dns_request;
    void *on_dns_request_context;
    bool is_tcp;
};

void dnsport_read(DNSPort *port);
void dnsport_flush(DNSPort *port);
void dnsport_on_ready(int socket, short flags, void *ctx);
void dnsport_free(DNSPort *port);
DNSMessage *dnsmessage_new();
void dnsmessage_free(DNSMessage *message); 
DNSRequest *dnsrequest_new();

void dnsport_flush(DNSPort *port) {

}

void dnsport_handle_request_bytes(DNSPort *port, uint8_t *bytes, ssize_t bytes_len, struct sockaddr *addr, socklen_t addr_len) 
{
    DNSRequest *request = dnsrequest_new();
    

}

void dnsport_read(DNSPort *port) {
    LOG_DEBUG("read");

    for (;;) {
        uint8_t packet[DNS_MAX_UDP_PACKET_SIZE];
        struct sockaddr addr;
        socklen_t addr_len;
        addr_len = sizeof(struct sockaddr_storage);
        ssize_t packet_len = recvfrom(port->socket, packet, DNS_MAX_UDP_PACKET_SIZE, 0, &addr, &addr_len);
        if (packet_len > 0) {
            LOG_DEBUG("read %d byte packet", (int)packet_len);
            dnsport_handle_request_bytes(port, packet, packet_len, &addr, addr_len);
            continue;
        }
        int err = evutil_socket_geterror(port->socket);
        if (IS_RETRYABLE(err))
            break;
        LOG_ERROR("Error %s (%d) while reading request.", evutil_socket_error_to_string(err), err);
        break;
    }
}


void dnsport_on_ready(int socket, short flags, void *ctx)
{
    DNSPort *port = (DNSPort *)ctx;
    LOG_DEBUG("port ready");
    if (flags & EV_WRITE) {
        dnsport_flush(port);
    } 

    if (flags & EV_READ) {
        dnsport_read(port);
    }
}


DNSPort *dnsport_new(struct event_base *event_base, int socket, bool is_tcp, OnDNSRequest on_dns_request, void *on_dns_request_context) 
{ 
    DNSPort *port = calloc(1, sizeof(DNSPort));
    port->event_base = event_base;
    port->socket = socket;
    port->on_dns_request = on_dns_request;
    port->is_tcp = is_tcp;
    port->on_dns_request_context = on_dns_request_context;
    event_assign(&port->event, port->event_base, port->socket, EV_READ | EV_PERSIST, dnsport_on_ready, port);

    if (event_add(&port->event, NULL) < 0) {
        dnsport_free(port);
        return NULL;
    }

    return port;
}

void dnsport_free(DNSPort *port) {
    free(port);
}

DNSQuestion *dnsquestion_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass)
{
    DNSQuestion *question = calloc(1, sizeof(DNSQuestion));
    size_t name_size = strlen(name);
    question->name = malloc(name_size + 1);
    memcpy(question->name, name, name_size);
    question->qtype = qtype;
    question->qclass = qclass;
    return question;
}

void dnsquestion_free(DNSQuestion *question)
{
    if (question->name != NULL)
        free(question->name);
    free(question);
}

DNSAnswer *dnsanswer_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass, int ttl, uint32_t address4, const char *cname, Buffer *txt)
{
    size_t name_len = strlen(name);

    DNSAnswer *answer = calloc(1, sizeof(DNSAnswer));
    if (name_len > 0) {
        answer->name = malloc(name_len + 1);
        memcpy(answer->name, name, name_len);
    }
    answer->qclass = qclass;
    answer->qtype = qtype;
    answer->ttl = ttl;
    switch (qtype) {
        case DNSTxtQueryType:
            answer->data.txt = buffer_copy(txt);
            break;
        case DNSCanonicalQueryType:    
            if (cname != NULL) {
                answer->data.cname = calloc(strlen(cname) + 1, 1);
                memcpy(answer->data.cname, cname, strlen(cname));
            } else {
                answer->data.cname = NULL;
            }
            break;
        case DNSHostQueryType:
            answer->data.address4 = address4;
            break;
        default:
            LOG_ERROR("unhandled query type");
    }
    return answer;
}

void dnsanswer_free(DNSAnswer *answer)
{
    if (answer->name != NULL)
        free(answer->name);
    switch(answer->qtype) {
        case DNSTxtQueryType:
            buffer_free(answer->data.txt);
            break;
        case DNSCanonicalQueryType:
            if (answer->data.cname != NULL)  
                free(answer->data.cname);
            break;
    }
    free(answer);
}

DNSRequest *dnsrequest_new()
{
    DNSRequest *request = calloc(1, sizeof(DNSRequest));
    request->message = dnsmessage_new();
    return request;
}

int dnsrequest_add_question(DNSRequest *request, const char *name, DNSQueryType
        qtype, DNSQueryClass qclass)
{
    list_append(request->message->questions, dnsquestion_new(name, qtype, qclass));
    return 0;
}

List *dnsmessage_answers(DNSMessage *message) {
    return message->answers;
}

List *dnsmessage_questions(DNSMessage *message) {
    return message->questions;
}

void dnsrequest_free(DNSRequest *request) {
    dnsmessage_free(request->message);
    free(request);
}

void dnsmessage_free(DNSMessage *message) { 
    list_free(message->answers, (ListFreeItemFunc)dnsanswer_free);
    list_free(message->additional, (ListFreeItemFunc)dnsanswer_free);
    list_free(message->nameservers, (ListFreeItemFunc)dnsanswer_free);
    list_free(message->questions, (ListFreeItemFunc)dnsquestion_free);
    free(message);
}

DNSMessage *dnsrequest_message(DNSRequest *req) {
    return req->message;
}

DNSMessage *dnsmessage_new() {
    DNSMessage *msg = calloc(1, sizeof(DNSMessage));
    msg->answers = list_new();
    msg->additional = list_new();
    msg->nameservers = list_new();
    msg->questions = list_new();
}


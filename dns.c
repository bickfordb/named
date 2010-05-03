#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
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
#include "util.h"
#include "rope.h"

#define IS_RETRYABLE(E) ((E) == EINTR || (E) == EAGAIN)
const int DNS_MAX_UDP_PACKET_SIZE = 1500;
const int DNS_MIN_UDP_PACKET_SIZE = 12 + 4;
static const int DNS_MAX_NAME_LENGTH = 256;
static const int DNS_HEADER_LENGTH = 12;
static const struct timeval DNS_TCP_TIMEOUT = { .tv_sec = 10, .tv_usec = 0};

struct _DNSPort
{
    struct event_base *event_base;
    struct event event;
    int socket;
    OnDNSRequest on_dns_request;
    void *on_dns_request_context;
    bool is_tcp;
};

typedef void (*DNSResourceRecordDataEncoder)(uint8_t **rrbuf, uint8_t *rrbuf_len, Buffer *buffer);

void dnsport_read_udp(DNSPort *port);
void dnsport_read_tcp(DNSPort *port);
void dnsport_flush(DNSPort *port);
void dnsport_on_ready(int socket, short flags, void *ctx);
void dnsport_free(DNSPort *port);
DNSMessage *dnsmessage_new();
void dnsmessage_free(DNSMessage *message);
static DNSResult dnsmessage_parse_question(DNSMessage *msg, uint8_t **body, size_t *body_len);
static DNSResult dnsmessage_parse_answer(DNSMessage *msg, uint8_t **body, size_t *body_len);
static DNSResult dnsmessage_parse_additional(DNSMessage *msg, uint8_t **body, size_t *body_len);
static DNSResult dnsmessage_parse_nameserver(DNSMessage *msg, uint8_t **body, size_t *body_len);
static DNSResult dns_parse_label(uint8_t *label, size_t label_len, uint8_t **bytes, size_t *bytes_len);
DNSQuestion *dnsquestion_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass);
DNSQuestion *dnsquestion_copy(DNSQuestion *other);
DNSRequest *dnsrequest_new(DNSPort *port, struct sockaddr *src_address, socklen_t src_address_len, DNSMessage *message, evutil_socket_t socket);
DNSMessage *dnsmessage_copy(DNSMessage *other);
void dnsresponse_free(DNSResponse *response);
Buffer *dns_encode_label(char *name);

void dnsport_flush(DNSPort *port) {

}

DNSResult dnsmessage_parse(DNSMessage *message, uint8_t *bytes, size_t bytes_len) {
    // Read the header
    uint8_t *pos = bytes;
    message->id = ntohs(*((uint16_t *)pos));
    pos++;
    pos++;

    message->is_query_response = *pos & 1;
    message->opcode = (*pos >> 1) & 0xf;
    message->is_authoritative_answer = (*pos >> 5) & 1;
    message->is_truncated = (*pos >> 6) & 1;
    message->is_recursion_desired = (*pos >> 7) & 1;
    pos++;
    message->is_recursion_available = *pos & 1;
    message->rcode = (*pos >> 4) & 0xf;
    pos++;
    uint16_t question_count = ntohs(*((uint16_t *)pos));
    pos += 2;
    uint16_t answer_count = ntohs(*((uint16_t *)pos));
    pos += 2;
    uint16_t nameserver_count = ntohs(*((uint16_t *)pos));
    pos += 2;
    uint16_t additional_count = ntohs(*((uint16_t *)pos));
    pos += 2;
    uint8_t *body = pos;
    size_t body_len = bytes_len - (body - bytes);
    DNSResult status = DNSOkResult;
    #define DNS_RUN_PARSER(P) { status = P; if (status != DNSOkResult) return status;}
    for (int i = 0; i < question_count; i++) {
        DNS_RUN_PARSER(dnsmessage_parse_question(message, &body, &body_len));
    }

    for (int i = 0; i < answer_count; i++) {
        DNS_RUN_PARSER(dnsmessage_parse_answer(message, &body, &body_len));
    }
    for (int i = 0; i < nameserver_count; i++) {
        DNS_RUN_PARSER(dnsmessage_parse_nameserver(message, &body, &body_len));
    }
    for (int i = 0; i < additional_count; i++) {
        DNS_RUN_PARSER(dnsmessage_parse_additional(message, &body, &body_len));
    }
    #undef DNS_RUN_PARSER
    if (body_len > 0)
        return DNSExtraBodyResult;
    return DNSOkResult;
}

static DNSResult dns_parse_label(uint8_t *label, size_t label_len, uint8_t **bytes, size_t *bytes_len) {
    __label__ label_too_long;
    __label__ body_too_short;
    

    if (label == NULL)
        return DNSGeneralFailureResult;
    size_t label_idx = 0;
    uint8_t pop() {
        if (*bytes_len == 0)
            goto body_too_short;
        char c = **bytes;
        *bytes = *bytes + 1;
        *bytes_len = *bytes_len - 1;
        return c;
    }
    void push(uint8_t c) {
        if (label_idx >= (label_len - 1))
            goto label_too_long;
        label[label_idx++] = c;
        label[label_idx] = 0;
    }
    uint8_t length = pop();
    while (length > 0) {
        while (length > 0) {
            push(pop());
            length--;
        }
        length = pop();
        push('.');
    }
    push('\0');
    return DNSOkResult;
body_too_short:
    return DNSBodyTooShortResult;
label_too_long:
    return DNSLabelTooLongResult;
}

static DNSResult dnsresourcerecord_parse(DNSResourceRecord **record, uint8_t **body, size_t *body_len) {
    char *label = calloc(DNS_MAX_NAME_LENGTH, 1);
    if (label == NULL)
        return DNSGeneralFailureResult;
    dns_parse_label(label, DNS_MAX_NAME_LENGTH, body, body_len);
    *body = *body + 4;
    free(label);
    return DNSOkResult;
}

static DNSResult dnsmessage_parse_answer(DNSMessage *msg, uint8_t **body, size_t *body_len) {
    DNSResourceRecord *record = NULL;
    DNSResult result = dnsresourcerecord_parse(&record, body, body_len);
    if (result != DNSOkResult)
        return result;
    if (record != NULL)
        list_append(msg->answers, record);
    return DNSOkResult;
}

static DNSResult dnsmessage_parse_additional(DNSMessage *msg, uint8_t **body, size_t *body_len) {
    DNSResourceRecord *record = NULL;
    DNSResult result = dnsresourcerecord_parse(&record, body, body_len);
    if (result != DNSOkResult)
        return result;
    if (record != NULL)
        list_append(msg->additional, record);
    return DNSOkResult;
}

static DNSResult dnsmessage_parse_nameserver(DNSMessage *msg, uint8_t **body, size_t *body_len) {
    DNSResourceRecord *record = NULL;
    DNSResult result = dnsresourcerecord_parse(&record, body, body_len);
    if (result != DNSOkResult)
        return result;
    if (record != NULL)
        list_append(msg->nameservers, record);
    return DNSOkResult;
}

static DNSResult dnsmessage_parse_question(DNSMessage *msg, uint8_t **body, size_t *body_len) {
    DNSQueryType qtype;
    DNSQueryClass qclass;
    size_t consumed = 0;
    char *label = calloc(DNS_MAX_NAME_LENGTH, 1);
    if (label == NULL)
        return DNSGeneralFailureResult;
    DNSResult status = dns_parse_label(label, DNS_MAX_NAME_LENGTH, body, body_len);
    if (status != DNSOkResult)
        return status;
    qtype = ntohs(**((uint16_t **)body));
    *body = *body + 2;
    *body_len = *body_len - 2;
    qclass = ntohs(**((uint16_t **)body));
    *body = *body + 2;
    *body_len = *body_len - 2;
    list_append(msg->questions, dnsquestion_new(label, qtype, qclass));
    free(label);
    return DNSOkResult;
}

void dnsport_handle_request(DNSPort *port, DNSRequest *request) {

}

char *dnsrequest_repr(DNSRequest *request) {
    char *message_repr = dnsmessage_repr(request->message);
    if (message_repr == NULL)
        return NULL;
    char *repr = NULL;
    asprintf(&repr, "{message:%s}", message_repr);
    free(message_repr);
    return repr;
}

char *dnsmessage_repr(DNSMessage *message) {
    char *questions_repr = list_repr(message->questions, (ListReprFunc)dnsquestion_repr);
    char *repr = NULL;
    int succ = asprintf(&repr, "{questions:%s}", questions_repr);
    if (succ >= 0 && questions_repr != NULL)
        free(questions_repr);
    return repr;
}

char *dnsquestion_repr(DNSQuestion *question) {
    char *repr = NULL;
    asprintf(&repr, "{name:\"%s\", qclass:%d, qtype:%d}", question->name, (int)question->qclass, (int)question->qtype);
    return repr;
}

void dnsport_handle_request_bytes(DNSPort *port, uint8_t *bytes, ssize_t bytes_len, struct sockaddr *addr, socklen_t addr_len)
{
    const int header_size = 12;
    if (bytes_len < header_size)
        return;
    DNSRequest *request = dnsrequest_new(port, addr, addr_len, NULL, -1);
    if (request == NULL)
        return;
    int status = dnsmessage_parse(request->message, bytes, bytes_len);
    if (status == DNSOkResult) {
        if (port->on_dns_request != NULL)
            port->on_dns_request(request, port->on_dns_request_context);
    } else
        LOG_ERROR("failed to parse message: %d", status);
    dnsrequest_free(request);
}

void dnsrequest_on_event(int socket, short events, void *context) {
    DNSRequest *request = (DNSRequest *)context;

    if (events & EV_READ) {
        uint8_t buf[512];
        ssize_t read_len = read(request->socket, buf, 512);
        if (read_len < 0) {
            if (!IS_RETRYABLE(read_len)) {
                dnsrequest_free(request);
                perror("read");
            }
            return;
        }
        if (read_len == 0)
            return;
        rope_append_bytes(request->request_buf, buf, read_len);
        if ((request->request_len < 0) && (rope_length(request->request_buf) > 2)) {
            Buffer *b = rope_slice(request->request_buf, 0, 2);
            request->request_len = ntohs(*((uint16_t *)buffer_data(b)));
            buffer_free(b);
        }
        if (request->request_len > (rope_length(request->request_buf) + 2)) {
            return;
        }
        // stop reading
        event_del(request->event);
        event_free(request->event);
        request->event = NULL;
        Buffer *b = rope_flatten(request->request_buf);
        if (request->request_len < buffer_length(b))
            LOG_ERROR("extra request bytes: %d", (int)(buffer_length(b) - request->request_len));

        int status = dnsmessage_parse(request->message, buffer_data(b) + 2, request->request_len);
        if (status == DNSOkResult) {
            char *repr = dnsrequest_repr(request);
            if (repr != NULL) {
                LOG_DEBUG("request: %s", repr);
                free(repr);
            }
            if (request->port->on_dns_request != NULL) {
                request->port->on_dns_request(request, request->port->on_dns_request_context);
            }
        } else {
            LOG_ERROR("failed to parse message: %d", status);
        }
        dnsrequest_free(request);
    } else {
        LOG_DEBUG("unhandled event: %d", (int)events);
        exit(1);
    }
}

void dnsport_read_tcp(DNSPort *port) {
    LOG_DEBUG("read tcp");
    struct sockaddr addr;
    socklen_t addr_len;
    int conn_sock = accept(port->socket, &addr, &addr_len);
    if (conn_sock < 0) {
        if (conn_sock == EWOULDBLOCK || conn_sock == EINTR)
            return;
        perror("accept");
        return;
    }

    DNSRequest *request = dnsrequest_new(port, &addr, addr_len, NULL, conn_sock);
    request->event = event_new(port->event_base, conn_sock, EV_READ | EV_PERSIST, dnsrequest_on_event, request);  
    request->request_len = -1;
    request->request_buf = rope_new();
    event_add(request->event, &DNS_TCP_TIMEOUT);
}



void dnsport_read_udp(DNSPort *port) {
    LOG_DEBUG("read udp");

    uint8_t packet[DNS_MAX_UDP_PACKET_SIZE];
    struct sockaddr addr;
    socklen_t addr_len;
    addr_len = sizeof(struct sockaddr_storage);
    ssize_t packet_len = recvfrom(port->socket, packet, DNS_MAX_UDP_PACKET_SIZE, 0, &addr, &addr_len);
    LOG_DEBUG("read %d byte packet", (int)packet_len);
    if (packet_len < 0) {
        if (!IS_RETRYABLE(packet_len))
            LOG_ERROR("Error %s (%d) while reading request.", evutil_socket_error_to_string((int)packet_len), (int)packet_len);
        return;
    }
    if (packet_len < DNS_MIN_UDP_PACKET_SIZE) {
        LOG_ERROR("packet size too small");
        return;
    }
    DNSRequest *request = dnsrequest_new(port, &addr, addr_len, NULL, -1);
    if (request == NULL)
        return;
    int status = dnsmessage_parse(request->message, packet, packet_len);
    if (status == DNSOkResult) {
        char *repr = dnsrequest_repr(request);
        if (repr != NULL) {
            free(repr);
        }
        if (port->on_dns_request != NULL)
            port->on_dns_request(request, port->on_dns_request_context);
    } else
        LOG_ERROR("failed to parse message: %d", status);
    dnsrequest_free(request);

}


void dnsport_on_ready(int socket, short flags, void *ctx)
{
    DNSPort *port = (DNSPort *)ctx;
    if (flags & EV_WRITE) {
        dnsport_flush(port);
    }
    if (flags & EV_READ) {
        if (port->is_tcp)
            dnsport_read_tcp(port);
        else
            dnsport_read_udp(port);
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
DNSQuestion *dnsquestion_copy(DNSQuestion *other) {
    if (other == NULL)
        return NULL;
    return dnsquestion_new(other->name, other->qtype, other->qclass);
}

DNSQuestion *dnsquestion_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass)
{
    if (name == NULL)
        return NULL;
    DNSQuestion *question = calloc(1, sizeof(DNSQuestion));
    question->name = string_copy(name);
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

DNSResourceRecord *dnsresourcerecord_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass, int ttl, Buffer *data)
{
    DNSResourceRecord *answer = calloc(1, sizeof(DNSResourceRecord));
    answer->name = string_copy(name);
    answer->qclass = qclass;
    answer->qtype = qtype;
    answer->ttl = ttl;
    answer->data = buffer_copy(data);
    return answer;
}

DNSResourceRecord *dnsresourcerecord_copy(DNSResourceRecord *other) {
    DNSResourceRecord *record = calloc(sizeof(DNSResourceRecord), 1);
    memcpy(record, other, sizeof(DNSResourceRecord));
    record->data = buffer_copy(other->data);
    record->name = string_copy(other->name);
    return record;
}



void dnsresourcerecord_free(DNSResourceRecord *answer)
{
    if (answer->name != NULL)
        free(answer->name);
    if (answer->data != NULL)
        buffer_free(answer->data);
    free(answer);
}

DNSRequest *dnsrequest_new(DNSPort *port, struct sockaddr *src_address, socklen_t src_address_len, DNSMessage *message, evutil_socket_t socket)
{
    DNSRequest *request = calloc(1, sizeof(DNSRequest));
    request->port = port;
    request->socket = socket;
    request->message = message != NULL ? dnsmessage_copy(message) : dnsmessage_new();
    request->src_address = malloc(src_address_len);
    request->src_address_len = src_address_len;
    memcpy(request->src_address, src_address, src_address_len);
    return request;
}


void dnsresponse_finish_udp(DNSResponse *response) {
    // do network sending things here!

    LOG_DEBUG("finishing response");
    if (response->response_buf == NULL) {
        LOG_DEBUG("encoding response");
        response->response_buf = dnsmessage_encode(response->message);
    }
    void *buf = buffer_data(response->response_buf) + response->sent_counter;
    size_t size = buffer_length(response->response_buf) - response->sent_counter;
    LOG_DEBUG("sending response (%d)", (int)size);
    ssize_t sent = sendto(response->request->port->socket, buf, size, 0, response->request->src_address, response->request->src_address_len); 
    if (sent != size) {
        LOG_ERROR("left over response!");
    }
    dnsresponse_free(response);
}

void dnsresponse_tcp_event(evutil_socket_t sock, short events, void *context) {
    DNSResponse *response = (DNSResponse *)context;
    if (events & EV_WRITE) {
        ssize_t written = write(sock, buffer_data(response->response_buf) + response->sent_counter, buffer_length(response->response_buf) - response->sent_counter);
        if (written < 0) {
            if ((written == EINTR) || (written == EAGAIN)) {
                return; 
            }
            LOG_ERROR("write error: %d", (int)written);
            goto cleanup;
        }
        response->sent_counter += written;
        if (response->sent_counter == buffer_length(response->response_buf)) {
            goto cleanup;
        }
    } else if (events & EV_TIMEOUT) {
        LOG_DEBUG("write timeout");
        goto cleanup;
    }
cleanup:
    close(sock);
    dnsresponse_free(response);
}

void dnsresponse_finish_tcp(DNSResponse *response) {
   // do network sending things here!
    if (response->response_buf != NULL) {
        LOG_ERROR("already encoded response");
        exit(1);
    }
    Buffer *msg_buf = dnsmessage_encode(response->message);
    response->response_buf = buffer_empty(buffer_length(msg_buf) + 2);
    memcpy(buffer_data(response->response_buf) + 2, buffer_data(msg_buf), buffer_length(msg_buf));
    buffer_free(msg_buf);
    *((uint16_t *)buffer_data(response->response_buf)) = htons((uint16_t)buffer_length(msg_buf));
    response->event = event_new(response->request->port->event_base, response->request->socket, EV_WRITE | EV_PERSIST, dnsresponse_tcp_event, response);
    event_add(response->event, &DNS_TCP_TIMEOUT);
    LOG_DEBUG("sending response");
}

void dnsresponse_finish(DNSResponse *response) { 
    if (response->request->port->is_tcp) 
        dnsresponse_finish_tcp(response);
    else
        dnsresponse_finish_udp(response);
}

void dnsmessage_encode_header(DNSMessage *message, Rope *stringbuf) {
    uint8_t bytes[DNS_HEADER_LENGTH];
    memset(bytes, 0, DNS_HEADER_LENGTH);
    uint8_t *pos = bytes;
    *((uint16_t *)pos) = htons(message->id);
    pos += 2;
    *pos = *pos | (message->is_query_response & 1);
    *pos = *pos | (htons(message->opcode) << 1);
    *pos = *pos | (message->is_authoritative_answer << 5);
    *pos = *pos | (message->is_truncated << 6);
    *pos = *pos | (message->is_recursion_desired << 7);
    pos++;
    *pos = *pos | (1 & message->is_recursion_available);
    *pos = *pos | ((message->rcode & 0xf) << 4);
    pos++;
    *((uint16_t *)pos) = htons(list_length(message->questions));
    pos += 2;
    *((uint16_t *)pos) = htons(list_length(message->answers));
    pos += 2;
    *((uint16_t *)pos) = htons(list_length(message->nameservers));
    pos += 2;
    *((uint16_t *)pos) = htons(list_length(message->additional));
    rope_append_bytes(stringbuf, bytes, DNS_HEADER_LENGTH);
    LOG_DEBUG("encoded header");
}

void dnsquestion_encode(DNSQuestion *question, Rope *string_buf)
{ 
    Buffer *label_buf = dns_encode_label(question->name);
    rope_append_buffer(string_buf, label_buf);
    buffer_free(label_buf);
    uint16_t dubbabytes[2];
    dubbabytes[0] = htons(question->qtype);
    dubbabytes[1] = htons(question->qclass);
    rope_append_bytes(string_buf, (uint8_t *)dubbabytes, 4);
}

/* Encode a name into a label.
 *
 * A label is sequence of up to 256 byte frames.  Each frame consists of a
 * length prefix byte N followed by N characters, eventually followed by a 0
 * byte.
 *
 * For example 'hi.there.com' is encoded as [2 'h' 'i' 5 't' h' 'e' 'r' 'e' 3
 * 'c' 'o' 'm' 0]
 */ 
Buffer *dns_encode_label(char *name) {
    size_t n = strlen(name);
    while ((n > 0) && (name[n - 1] == '.'))
        n--;
    uint8_t buf[n + 2];
    memset(buf, 0, sizeof(buf));
    memcpy(buf + 1, name, n);
    uint8_t *p = buf + n;
    buf[n + 1] = 0;
    while (p >= buf) {
        uint8_t chunk_size = 0;
        while ((p > buf) && (*p != '.')) {
            chunk_size++;
            p--;
        }
        if (chunk_size != 0)
            *p = chunk_size;
        p--;
    }
    return buffer_new(buf, sizeof(buf));
}

void dnsresourcerecord_encode(DNSResourceRecord *rr, Rope *string_buf)
{
    Buffer *label_buf = dns_encode_label(rr->name);
    rope_append_buffer(string_buf, label_buf);
    buffer_free(label_buf);
    uint16_t qtype = htons(rr->qtype);
    uint16_t qclass = htons(rr->qclass);
    int32_t ttl = 0;
    rope_append_bytes(string_buf, (void *)&qtype, sizeof(qtype));
    rope_append_bytes(string_buf, (void *)&qclass, sizeof(qclass));
    rope_append_bytes(string_buf, (void *)&ttl, sizeof(ttl));
    switch (rr->qtype) {
    case DNSTxtQueryType:
        {
            size_t remaining = buffer_length(rr->data);
            size_t offset = 0;
            Rope *r = rope_new();
            while (remaining > 0) {
                const uint8_t max_chunk_size = 255;
                uint8_t chunk_size = remaining < max_chunk_size ? remaining : max_chunk_size;
                uint8_t chunk[chunk_size + 1];
                // The first byte is the chunk size
                chunk[0] = chunk_size;
                memcpy(&chunk[1], buffer_data(rr->data) + offset, sizeof(chunk) - 1);
                offset += chunk_size;
                remaining -= chunk_size;
                rope_append_bytes(r, chunk, sizeof(chunk));
            }
            Buffer *b = rope_flatten(r);
            uint16_t size = htons(buffer_length(b));
            rope_append_bytes(string_buf, (const void *)&size, 2);
            rope_append_buffer(string_buf, b);
            buffer_free(b);
            break;
        }
    default:
        {
            LOG_DEBUG("unknown resource record type");
            uint16_t size = buffer_length(rr->data);
            rope_append_bytes(string_buf, (uint8_t *)&size, 2); 
            rope_append_buffer(string_buf, rr->data);
            break;
        }
    }
}

Buffer *dnsmessage_encode(DNSMessage *message)
{
    Rope *string_buf = rope_new();
    dnsmessage_encode_header(message, string_buf);
   
    void enc_question(List *l, void *ctx, void *item, bool *keep_going) {
        DNSQuestion *question = (DNSQuestion *)item;
        dnsquestion_encode(question, string_buf);
    }
    void enc_rr(List *l, void *ctx, void *item, bool *keep_going) {
        DNSResourceRecord *record = (DNSResourceRecord *)item;
        dnsresourcerecord_encode(record, string_buf);
    }
    list_iterate(message->questions, (ListIterateFunc)enc_question, NULL);
    list_iterate(message->answers, (ListIterateFunc)enc_rr, NULL);
    list_iterate(message->nameservers, (ListIterateFunc)enc_rr, NULL);
    list_iterate(message->additional, (ListIterateFunc)enc_rr, NULL);
    return rope_flatten(string_buf);
}

void dnsresponse_free(DNSResponse *response) {
    if (response->event != NULL) {
        event_del(response->event);
        event_free(response->event);
    }
    dnsrequest_free(response->request);
    dnsmessage_free(response->message);
    if (response->response_buf != NULL)
        buffer_free(response->response_buf);
    free(response);
}

int dnsrequest_add_question(DNSRequest *request, const char *name, DNSQueryType
        qtype, DNSQueryClass qclass)
{
    list_append(request->message->questions, dnsquestion_new(name, qtype, qclass));
    return 0;
}

void dnsrequest_free(DNSRequest *request) {
    free(request->src_address);
    if (request->event != NULL) {
        event_del(request->event);
        event_free(request->event);
    }
    if (request->request_buf != NULL)
        rope_free(request->request_buf);
    dnsmessage_free(request->message);
    free(request);
}

void dnsmessage_free(DNSMessage *message) {
    list_free(message->answers, (ListFreeItemFunc)dnsresourcerecord_free);
    list_free(message->additional, (ListFreeItemFunc)dnsresourcerecord_free);
    list_free(message->nameservers, (ListFreeItemFunc)dnsresourcerecord_free);
    list_free(message->questions, (ListFreeItemFunc)dnsquestion_free);
    free(message);
}

DNSMessage *dnsmessage_new() {
    DNSMessage *msg = calloc(1, sizeof(DNSMessage));
    if (msg == NULL)
        return msg;
    msg->answers = list_new();
    msg->additional = list_new();
    msg->nameservers = list_new();
    msg->questions = list_new();
    return msg;
}

DNSMessage *dnsmessage_copy(DNSMessage *other) {
    DNSMessage *msg = calloc(sizeof(DNSMessage), 1);
    memcpy(msg, other, sizeof(DNSMessage));
    msg->answers = list_copy(other->answers, (ListCopyFunc)dnsresourcerecord_copy);
    msg->additional = list_copy(other->additional, (ListCopyFunc)dnsresourcerecord_copy);
    msg->nameservers = list_copy(other->nameservers, (ListCopyFunc)dnsresourcerecord_copy);
    msg->questions = list_copy(other->questions, (ListCopyFunc)dnsquestion_copy);
    return msg;
}

DNSResponse *dnsresponse_new(DNSRequest *request) {
    DNSResponse *response = calloc(sizeof(DNSResponse), 1);
    response->request = dnsrequest_new(request->port, request->src_address, request->src_address_len, request->message, request->socket);
    response->message = dnsmessage_copy(response->request->message);
    response->message->is_query_response = 1;
    return response;
}



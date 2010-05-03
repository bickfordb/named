#include <event2/event.h>

#ifndef __DNS_H__
#define __DNS_H__

#include "list.h"
#include "buffer.h"
#include "rope.h"

/* Records whose type is <= 16 are described in RFC 1035 */
typedef enum {
    DNSHostQueryType       = 1,  // A
    DNSNameServerQueryType = 2,  // NS
    DNSCanonicalQueryType  = 5,  // CNAME
    DNSSOAQueryType        = 6,  // SOA
    DNSPointerQueryType    = 12, // PTR
    DNSMailQueryType       = 15, // MX
    DNSTxtQueryType        = 16, // TXT
    DNSQuadAQueryType      = 28, // AAAA, RFC 3596
    DNSWildcardQueryType   = 255
} DNSQueryType;

/* Other classes aren't important, see sec 3.2.4 of RFC 1035 for details */
typedef enum {
    DNSInternetQueryClass = 1,
    DNSWildcardQueryClass = 255
} DNSQueryClass;

typedef struct _DNSAnswer DNSAnswer;
typedef struct _DNSBase DNSBase;
typedef struct _DNSMessage DNSMessage;
typedef struct _DNSPort DNSPort;
typedef struct _DNSQuestion DNSQuestion;
typedef struct _DNSRequest DNSRequest;
typedef struct _DNSResourceRecord DNSResourceRecord;
typedef struct _DNSResponse DNSResponse;
typedef void (*OnDNSRequest)(struct _DNSRequest *req, void *context);

struct _DNSMessage
{
    uint16_t id;
    int opcode;
    int is_query_response : 1;
    int is_recursion_desired : 1;
    int is_truncated : 1;
    int is_recursion_available : 1;
    int is_authoritative_answer : 1;
    uint8_t rcode;
    List *questions;
    List *answers;
    List *nameservers;
    List *additional;
};


struct _DNSRequest
{
   DNSMessage *message;
   DNSPort *port;
   struct sockaddr *src_address;
   socklen_t src_address_len;

   // For TCP connections:
   struct event *event;
   ssize_t request_len;
   Rope *request_buf;
   int socket;
};

typedef enum
{
    DNSGeneralFailureResult = -1,
    DNSLabelTooLongResult = -2,
    DNSExtraBodyResult = -3,
    DNSBodyTooShortResult = -4,
    DNSOkResult = 0
} DNSResult;

struct _DNSResourceRecord
{
    char *name;
    DNSQueryType qtype;
    DNSQueryClass qclass;
    uint32_t ttl;
    Buffer *data;
};

struct _DNSQuestion
{
    char *name;
    DNSQueryType qtype;
    DNSQueryClass qclass;
};

struct _DNSResponse
{
    DNSRequest *request;
    DNSMessage *message;
    Buffer *response_buf;
    size_t sent_counter;
    struct event *event;
};

DNSPort *dnsport_new(struct event_base *event_base, int socket, bool is_tcp, OnDNSRequest on_dns_request, void *on_dns_request_context);
DNSMessage *dnsrequest_message(DNSRequest *);
List *dnsmessage_answers(DNSMessage *);
List *dnsmessage_questions(DNSMessage *);
char *dnsrequest_repr(DNSRequest *request);
char *dnsmessage_repr(DNSMessage *message);
char *dnsquestion_repr(DNSQuestion *question);
DNSResourceRecord *dnsresourcerecord_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass, int ttl, Buffer *data);
void dnsresourcerecord_free(DNSResourceRecord *record);
DNSResponse *dnsresponse_new(DNSRequest *request);
void dnsrequest_free(DNSRequest *request);
DNSMessage *dnsresponse_message(DNSResponse *response);
void dnsresponse_finish(DNSResponse *response);
DNSResourceRecord *dnsresourcerecord_copy(DNSResourceRecord *other);
Buffer *dnsmessage_encode(DNSMessage*);
void dnsport_free(DNSPort *);

#endif // __DNS_H__

#include <event2/event.h>

#ifndef __DNS_H__
#define __DNS_H__

#include "list.h"

struct _DNSRequest;
struct _DNSBase;
struct _DNSAnswer;
struct _DNSQuestion;
struct _DNSPort;
struct _DNSMessage;
typedef struct _DNSBase DNSBase;
typedef struct _DNSRequest DNSRequest;
typedef struct _DNSResponse DNSResponse;
typedef struct _DNSAnswer DNSAnswer;
typedef struct _DNSQuestion DNSQuestion;
typedef struct _DNSPort DNSPort;
typedef struct _DNSMessage DNSMessage;

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

typedef void (*OnDNSRequest)(DNSRequest *req, void *context);
DNSPort *dnsport_new(struct event_base *event_base, int socket, bool is_tcp, OnDNSRequest on_dns_request, void *on_dns_request_context); 
DNSMessage *dnsrequest_message(DNSRequest *);
List *dnsmessage_answers(DNSMessage *);
List *dnsmessage_questions(DNSMessage *);

#endif // __DNS_H__


#ifndef __DNS_H__
#define __DNS_H__

#include "list.h"

struct _DNSRequest;
struct _DNSAnswer;
struct _DNSQuestion;
typedef struct _DNSRequest DNSRequest;
typedef struct _DNSAnswer DNSAnswer;
typedef struct _DNSQuestion DNSQuestion;

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

#endif // __DNS_H__


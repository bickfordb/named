#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <event2/util.h>

#include "dns.h"
#include "list.h"

struct _DNSRequest
{
    List *questions;
    List *answers;
};

struct _DNSAnswer
{
    char *name;
    DNSQueryClass qclass;
    DNSQueryType qtype;
    int ttl;
    int data_len;
    void *data;
};

struct _DNSQuestion
{
    char *name;
    DNSQueryClass qclass;
    DNSQueryType qtype;
};

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

DNSAnswer *dnsanswer_new(const char *name, DNSQueryType qtype, DNSQueryClass qclass, int ttl, int data_len, void *data)
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
    answer->data_len = data_len;
    if (data_len > 0) {
        answer->data = malloc(data_len);
        memcpy(answer->data, data, data_len);
    }
    return answer;
}

void dnsanswer_free(DNSAnswer *answer)
{
    if (answer->name != NULL)
        free(answer->name);
    if (answer->data != NULL)
        free(answer->data);
    free(answer);
}

DNSRequest *dnsrequest_new()
{
    DNSRequest *request = calloc(1, sizeof(DNSRequest));
    return request;
}

int dnsrequest_add_question(DNSRequest *request, const char *name, DNSQueryType
        qtype, DNSQueryClass qclass)
{
    request->questions = list_cons(request->questions, dnsquestion_new(name, qtype, qclass));
}

int dnsrequest_add_answer(DNSRequest *request, const char *name, DNSQueryType
        qtype, DNSQueryClass qclass, int ttl, int data_len, void *data)
{
    request->answers = list_cons(request->answers, dnsanswer_new(name, qtype, qclass, ttl, data_len, data));
}

void dnsrequest_free(DNSRequest *request) {
    list_free(request->answers, (ListFreeItemFunc)dnsanswer_free);
    list_free(request->questions, (ListFreeItemFunc)dnsquestion_free);

}


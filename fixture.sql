
-- TYPE value and meaning A 
-- 
-- 1 a host address NS 
-- 2 an authoritative name server MD 
-- 3 a mail destination (Obsolete - use MX) MF 
-- 4 a mail forwarder (Obsolete - use MX) CNAME 
-- 5 the canonical name for an alias SOA 
-- 6 marks the start of a zone of authority MB 
-- 7 a mailbox domain name (EXPERIMENTAL) MG 
-- 8 a mail group member (EXPERIMENTAL) MR 
-- 9 a mail rename domain name (EXPERIMENTAL) NULL 
-- 10 a null RR (EXPERIMENTAL) WKS 
-- 11 a well known service description PTR 
-- 12 a domain name pointer HINFO 
-- 13 host information MINFO 
-- 14 mailbox or mail list information MX 
-- 15 mail exchange TXT 
-- 16 text strings
-- 255 *

-- CLASS
-- 1 - internets
-- 255 -- all

delete from responses where name = 'foo.' or name = 'foo.com.';
insert into responses (name, qclass, qtype, ttl, rdata) values ('foo.', 1, 16, 300, 'hey');
insert into responses (name, qclass, qtype, ttl, rdata) values ('foo.com.', 1, 16, 300, 'hey foo.com');
insert into responses (name, qclass, qtype, ttl, rdata) values ('foo.com.', 1, 1, 300, '192.168.1.1');
insert into responses (name, qclass, qtype, ttl, rdata) values ('www.foo.com.', 1, 5, 300, 'foo.com');
 

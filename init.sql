
create table if not exists responses (
    id integer primary key,
    name text key,
    qclass integer,
    qtype integer,
    ttl integer,
    data text
);

create index responses_name_idx on responses (name);

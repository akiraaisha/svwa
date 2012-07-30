drop table if exists users;
create table users (
    id integer primary key autoincrement,
    username string not null,
    password string not null,
    salt string not null,
    coins int not null default 0,
    group_id int not null default 0,
    signature string
);
drop table if exists forums;
create table forums (
    id integer primary key autoincrement,
    name string not null,
    description string,
    thread_count integer not null default 0,
    post_count integer not null default 0
);

drop table if exists threads;
create table threads (
    id integer primary key autoincrement,
    author integer not null,
    forum integer not null,
    title string not null,
    time timestamp not null,
    post_count integer not null default 0,
    FOREIGN KEY (author) REFERENCES users(id),
    FOREIGN KEY (forum) REFERENCES forums(id)
);

drop table if exists posts;
create table posts (
    id integer primary key autoincrement,
    author integer not null,
    thread integer not null,
    message string not null,
    time timestamp not null,
    first_post boolean not null default false,
    FOREIGN KEY (author) REFERENCES users(id),
    FOREIGN KEY (thread) REFERENCES threads(id)
);

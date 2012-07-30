import sqlite3
from contextlib import closing
from flask import g
from globals import app
import util
import hashlib

### DATABASE FUNCTIONS ###
def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    app.logger.debug('QUERY: ' + query)
    cur = g.cursor.execute(query, args)
    g.db.commit()
    rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv

def create_user(username, password):
    pw_hash = hashlib.sha512(password + app.config['SECRET_KEY']).hexdigest()
    query_db('insert into users (username, password) VALUES (?, ?)', [username, pw_hash])

def create_forum(name, description):
    query_db('INSERT INTO forums (name, description) VALUES (?, ?)', [name, description])

def insert_thread(forum_id, topic, message, user_id):
    timestamp = str(util.timestamp())
    query_db('INSERT INTO threads (author, forum, title, time, post_count)\
                VALUES (' + str(user_id) + ',' + str(forum_id) + ',"' + topic + '",' + timestamp + ',0)')
    thread_id = g.cursor.lastrowid
    app.logger.debug("Inserting thread #" + str(thread_id))
    query_db('UPDATE forums SET thread_count = thread_count + 1 WHERE id = ' + str(forum_id))
    insert_post(forum_id, thread_id, message, user_id, timestamp)
    return thread_id

def drop_thread(thread_id):
    t = query_db('SELECT post_count, forum FROM threads WHERE id = ?', [thread_id], one=True)
    forum_id = t['forum']
    post_count = t['post_count']
    query_db('DELETE FROM threads WHERE id = ?', [thread_id])
    query_db('UPDATE forums SET thread_count = thread_count - 1, post_count = post_count - ? WHERE id = ?', [post_count, forum_id])

def insert_post(forum_id, thread_id, message, user_id, first_post=False, timestamp=None):
    if timestamp is None:
        timestamp = str(util.timestamp())
    query_db('INSERT INTO posts (author, thread, message, time, first_post) VALUES\
            (' + str(user_id) + ',' + str(thread_id) + ',"' + message + '",' + timestamp +',' + str(b2i(first_post)) + ')')
    query_db('UPDATE forums SET post_count = post_count + 1 WHERE id = ' + str(forum_id))
    query_db('UPDATE threads SET post_count = post_count + 1 WHERE id = ' + str(thread_id))

def drop_post(post_id):
    thread = query_db('SELECT thread FROM posts WHERE id = ?', [post_id], one=True)['thread']
    forum = query_db('SELECT forum FROM threads WHERE id = ?', [thread], one=True)['forum']
    query_db('DELETE FROM posts WHERE id = ?', [post_id])
    query_db('UPDATE forums SET post_count = post_count - 1 WHERE id = ?', [forum])
    query_db('UPDATE threads SET post_count = post_count - 1 WHERE id = ?', [thread])

def set_user_group(user, gid):
    query_db('UPDATE users SET group_id = ? WHERE username = ?', [gid, user])

##### POPULATE DATABASE WITH THE FOLLOWING FUNCTION #####
def populate_database():
    create_user("kyle", "password")
    set_user_group("kyle", app.config['ADMIN_GROUP_ID'])
    create_user("admin", "h1ghlys3cur3")
    create_user("bob", "bob")
    create_user("alice", "alice")
    create_user("zero", "zero")
    create_forum('General', 'A place for general discussion about SVWA')
    create_forum('Vulnerabilities', 'Found a vulnerability in SVWA? Post it here!')
    create_forum('Tutorials', 'Post all of your super informative tutorials here for everyone to learn from.')
    create_forum('Other', 'Some other forumz')
    create_forum('Random Stuff', '... another one i guess')
    insert_thread(1, 'Hello World!', 'Hello World!', 1)
    insert_thread(2, 'Whats up?', 'asdkljasdklajsdkl', 2)
    insert_thread(3, 'Free Stuff Here', 'jk, just stole your moneyz through XSS', 3)
    insert_thread(4, 'Random thread', 'random stuff?', 4)
    insert_thread(1, 'More Topics', 'shouldve just generated these somehow', 4)
    insert_thread(1, 'Still need more...', 'keep going!', 3)
    insert_thread(1, 'lookin good', 'zzz', 2)
    insert_thread(2, 'SPAM', 'SPAM', 2)

### helper functions ###
def i2b(n):
    return n == 1

def b2i(b):
    return 1 if b else 0

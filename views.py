from flask import session, render_template, request, flash, url_for, redirect, jsonify, send_from_directory
from werkzeug import secure_filename
from db import query_db, insert_post, insert_thread, populate_database, init_db, drop_thread, drop_post
import os
from globals import app

### CONSTANTS ###
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

### VIEWS ###
@app.route('/')
def home():
    forums = None
    if session.get('logged_in'):
        forums = query_db('SELECT * FROM forums')
    return render_template('home.html', forums=forums)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = query_db('SELECT * FROM users WHERE username = "' + username + '" AND password = "' + password + '"', one=True)
    if user is None:
        flash('Login failed.')
    else:
        session['session_id'] = user['id']
        session['user_id'] = user['id']
        session['logged_in'] = True
        flash('Welcome ' + user['username'])
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('session_id', None)
    session.pop('logged_in', None)
    session.pop('user_id', None)
    flash('You have been logged out')
    return redirect(url_for('home'))

@app.route('/forum/<int:forum_id>')
def view_forum(forum_id):
    threads = query_db('SELECT threads.id AS id, threads.title AS name, threads.post_count AS post_count, users.username AS author, threads.author AS user_id FROM threads, users WHERE threads.author = users.id AND forum = ' + str(forum_id))
    forum_name = query_db('SELECT name FROM forums WHERE id = ' + str(forum_id), one=True)
    return render_template('view_forum.html', threads=threads, forum_id=forum_id, forum_name=forum_name['name'])

@app.route('/thread/<int:thread_id>')
def view_thread(thread_id):
    query = query_db('SELECT users.username AS author, posts.author AS user_id, posts.id AS id, posts.message AS message, datetime(posts.time, "unixepoch") AS time FROM posts, users WHERE thread = ? AND users.id = posts.author ORDER BY time', [thread_id])
    topic = query_db('SELECT title,forum FROM threads WHERE id = ?', [thread_id], one=True)
    forum = query_db('SELECT name FROM forums WHERE id = ?', [topic['forum']], one=True)
    return render_template('view_thread.html', thread_id=thread_id, posts=query, thread_topic=topic['title'], forum_id=topic['forum'], forum_name=forum['name'])

@app.route('/thread/new/<int:forum_id>', methods=['GET', 'POST'])
def new_thread(forum_id):
    if request.method == 'POST':
        thread_id = insert_thread(forum_id, request.form['topic'], request.form['message'], session['user_id'])
        return redirect(url_for('view_thread', thread_id=thread_id))
    return render_template('new_thread.html', forum_id=forum_id)

#ajax post deletion
@app.route('/thread/delete/<int:thread_id>', methods=['POST'])
def delete_thread(thread_id):
    q = query_db('SELECT author FROM threads WHERE id = ?', [thread_id], one=True)
    pred = (q['author'] == session['user_id'])
    if pred:
        drop_thread(thread_id)
    return jsonify(delete=pred)

@app.route('/post/new/<int:thread_id>', methods=['GET', 'POST'])
def new_post(thread_id):
    if request.method == 'POST':
        forum_id = query_db('SELECT forum FROM threads WHERE id = ?', [thread_id], one=True)['forum']
        insert_post(forum_id, thread_id, request.form['message'], session['user_id'])
        return redirect(url_for('view_thread', thread_id=thread_id))
    return render_template('new_post.html', thread_id=thread_id)

@app.route('/post/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    q = query_db('SELECT author, first_post FROM posts WHERE id = ?', [post_id], one=True)
    pred = (q['author'] == session['user_id']) and not q['first_post']
    if pred:
        drop_post(post_id)
    return jsonify(delete=pred)

@app.route('/admin', methods=['GET', 'POST'])
def admin_home():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'populate_db':
            populate_database()
        elif action == 'reset_db':
            init_db()
            populate_database()
        else:
            flash('Unknown action.')
    return render_template('admin_home.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file and (not app.config['SECURE'] or allowed_file(file.filename)):
            filename = secure_filename(file.filename) if app.config['SECURE'] else file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash("Your file was uploaded to " + request.url_root + app.config['UPLOAD_FOLDER'] + "/" + filename)
            redirect(url_for('home'))
    return render_template('upload_file.html')

@app.route('/upload/search', methods=['POST','GET'])
def search_uploads():
    return jsonify(files=os.system('ls ' + app.config['UPLOAD_FOLDER'] + ' | grep ' + request.form['filename']))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

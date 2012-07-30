from globals import app
import views
from flask import g, request, session, abort
from db import connect_db, populate_database
from util import generate_random_string

#config
DATABASE = 'svwa.db'
DEBUG = True
SECRET_KEY = 'svwa dev key'
USERNAME = 'admin'
PASSWORD = 'letmein1'
SECURE = True
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024
ADMIN_GROUP_ID = 4

# Setup main app object
app.config.from_object(__name__)

### MISC FUNCTIONS ###
@app.before_request
def before_request():
    g.db = connect_db()
    g.cursor = g.db.cursor()
    if app.config['SECURE']:
        csrf_protect()

@app.teardown_request
def teardown_request(exception):
    g.db.close()

### CSRF PROTECTION FUNCTIONS ###
def csrf_protect():
    if request.method == 'POST':
        token = session.pop('_csrf_token', None)
        print token
        if not token or token != request.form.get('_csrf_token'):
            abort(403)

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = generate_random_string()
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token
### END CSRF PROTECTION ###

### Entry Point ###
if __name__ == '__main__':
    app.run(host='ubuntu-vm')

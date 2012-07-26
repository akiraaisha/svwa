from globals import app
import views
from flask import g
from db import connect_db

#config
DATABASE = 'svwa.db'
DEBUG = True
SECRET_KEY = 'svwa dev key'
USERNAME = 'admin'
PASSWORD = 'letmein1'
SECURE = False
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# Setup main app object
app.config.from_object(__name__)

### MISC FUNCTIONS ###
@app.before_request
def before_request():
    g.db = connect_db()
    g.cursor = g.db.cursor()

@app.teardown_request
def teardown_request(exception):
    g.db.close()

### Entry Point ###
if __name__ == '__main__':
    app.run(host='ubuntu-vm')

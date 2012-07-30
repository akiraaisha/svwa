import time
from flask import session
from globals import app
import hashlib
import base64
import os

def timestamp():
    return int(time.time())

def generate_random_string():
    user = ''
    if 'username' in session:
        user = session['username']
    else:
        user = 'guest'
    sha = hashlib.sha256()
    sha.update(user)
    sha.update(os.urandom(32))
    sha.update(app.config['SECRET_KEY'])
    return base64.b64encode(sha.digest())



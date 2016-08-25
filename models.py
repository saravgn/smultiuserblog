import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# secret: used for cookies
secret = 'pol.wehr.sopfj-sloed,fka$bcnq^hskale.alo'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# takes a val and returns that value, a pipe and then the hmac of that val
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# takes one secure_val and checks if it is valid
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# user stuff
# returns a string of 5 random letters
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# makes a password hash. It returns the salt, the hash version of
# the name, password and salt
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s,%s' % (salt, h)


# returns True if a user's password matches its hash.
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# creates the ancestor element in db to store
# all the users
def users_key(group='default'):
    return db.Key.from_path('users', group)


# the user object that will be stored in the db.
# It inherits from db.model.
# A user has a name, a password hash and email(optional)
class User(db.Model):
    name = db.StringProperty(required=True)
    # only store hash password
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    # decorator: you can call the by_id method on User object,
    # it dosn't have to be instance of User, so the first parameter
    # is not "self" (instance) but "cls" for class to refere to User class
    # not to an instance of user.
    # so give it an id (uid), and it calls the get_by_id function
    # to load the user on the datastore

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # looks up a user by its name
    # this is datastore procedural code instead of GQL
    # it is like select * from name where name = name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    # creates a new user object

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)
    # User.login, if the name and password entered in match the password
    # hash, from that object "u" with that name in the db, it returns the
    # user

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty()
    likes_average = db.IntegerProperty(default=0)
    likes = db.IntegerProperty(default=0)
    unlikes = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# this is the comment class
class Comment(db.Model):
    id_post = db.IntegerProperty()
    content = db.TextProperty()
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Likes(db.Model):
    idlike = db.StringProperty()
    idUnlike = db.StringProperty()
    author_like = db.StringProperty()
    post_id = db.StringProperty()
    likes_average = db.IntegerProperty(default=0)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

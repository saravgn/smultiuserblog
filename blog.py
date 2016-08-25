import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db
from models import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# parent class for all the handlers
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# sets a cookie with name as name and the secured val as value
# the expiring time is not specified so by default this cookie will
# expire when the browser is closed
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))


# if the cookie exists and passes the check-secure-val return
# cookie val
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
# if cookie_val and check_secure_val return cookie_val
        return cookie_val and check_secure_val(cookie_val)


# sets a secure cookie, with name user_id and val  user's ID
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))


# substitudes the cookie user-id with nothing, keep the same path
# so that overwrites the same cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


# checks for the user cookie (user_id); if it exists,
# store in self.user the actual user object.
# it's run in every request and just checks if user is
# logged in or not. And it is called by the App Engine framework
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    def get(self):
        self.render("mainpage.html")


# this handler class manages the blog page, it renders to front.html
# which renders to post.html which contains the button edit
# in the post form to edit a post
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        comments = db.GqlQuery('SELECT * FROM Comment ORDER BY created DESC')

        ##########################
        # UTILITIES

        # delete all comments
        # for comment in comments:
        # db.delete(comment)

        # delete all posts
        # for post in posts:
        # db.delete(post)

        ##########################

        self.render('front.html', posts=posts, comments=comments)

    def post(self):
        # Logged out users are redirected to the login page when attempting to
        # create, edit, delete, or like a blog post.
        if not self.user:
            self.redirect("/login")

        else:
            # post stuff
            post_id = self.request.get('post_id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            authorPost = post.author
            posts = greetings = Post.all().order('-created')
            delete_post_flag = self.request.get('delete_post_flag')
            edit_post_flag = self.request.get('edit_post_flag')
            edit_comment_flag = self.request.get('edit_comment_flag')
            like_flag = self.request.get('like_flag')
            # user stuff
            username = self.user.name
            # comment stuff
            comment_flag = self.request.get('comment_flag')
            commentContent = self.request.get('commentContent')
            deletecomment = self.request.get('delete_comment_flag')
            comment_id = self.request.get('comment_id')

            # COMMENT STUFF
            # Permissions:
            # Only signed in users can post comments. Users can only
            # edit and delete comments they themselves have made.

            # edit comment
            if edit_comment_flag == "zero":
                return self.redirect('/editcomment/%s' % str(comment_id))

            # new comment: the author of the post cannot comment it
            if comment_flag == "zero":
                if(authorPost == username):
                    error = "Sorry %s you cannot comment your own post!" % username  # noqa
                    return self.render('front.html', posts=posts, error=error)
                # yes add comment:if you are not the author of the post
                else:
                    if commentContent:
                        commentAuthor = self.user.name
                        # create an istance of coment
                        c = Comment(id_post=int(post_id),
                                    content=commentContent,
                                    author=commentAuthor)
                        c.put()
                        return self.redirect('/blog/?')
                    # no add comment:no content
                    else:
                        error = "Sorry %s there is no content to add!" % username  # noqa
                        return self.render('front.html',
                                           posts=posts,
                                           error=error)

            # delete comment: Only the author can delete a comment
            if(deletecomment == "zero"):
                return self.redirect('/deletecomment/%s' % str(comment_id))

            # POST STUFF
            # Logged in users can create, edit, or delete blog posts they
            # themselves have created.

            # delete post: the author of the post can delete it
            elif(authorPost == username and delete_post_flag == "zero"):
                db.delete(post)
                comments = Comment.all()
                self.redirect('/blog/?')
            # no delete post: only the author of the post can delete it
            elif(authorPost != username and delete_post_flag == "zero"):
                error = "Sorry %s you can only delete your own posts!" % username  # noqa
                comments = Comment.all()
                self.render('front.html',
                            posts=posts,
                            error=error,
                            comments=comments)

            # edit post: the author of the post can edit it
            if(edit_post_flag == "zero"):
                return self.redirect('/editpost/%s' % str(post.key().id()))

            # like post: not for post author
            if(like_flag == "zero"):
                return self.redirect('/likepost/%s' % str(post.key().id()))


class EditPost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        posts = greetings = Post.all().order('-created')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return self.render("error404.html")
        subject=post.subject
        content=post.content
        authorPost = post.author
        username = self.user.name
        if(authorPost == username):
            self.render("editpost.html",
                        p=post,
                        subject=post.subject,
                        content=post.content,
                        username=username,
                        author=authorPost)
        else:
            error = "Sorry %s you can only edit your own posts!" % username  # noqa
            return self.render("editposterror.html",
                               p=post,
                               error=error)


    def post(self, par):
        post_id = self.request.get('post_id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')
        username = self.user.name
        authorPost = post.author
        # check for content and subject
        if subject and content:
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')
            post.put()
            return self.redirect('/blog/%s' % str(post.key().id()))
        # button "done" to edit the post with no content or subject
        else:
            error = "subject or content, please!"
            return self.render("editpost.html",
                               p=post,
                               subject=subject,
                               content=content,
                               username=username,
                               author=authorPost,
                               error=error)


class LikePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            return self.redirect('/login')
        posts = greetings = Post.all().order('-created')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return self.render("error404.html")
        authorPost = post.author
        username = self.user.name
        # YES ADD LIKE POST: not the post author
        if(authorPost != username):
            likes = Likes.all()
            if likes.get():
                idlike = post_id+username
                likes_new = db.GqlQuery('SELECT * FROM Likes WHERE idlike = :1',  # noqa
                                        idlike)
                likes_new_average = post.likes_average
                # if (likes_new.get() and likes_new_average!=0):
                if (likes_new.get() and likes_new_average != 0):
                    error = "Sorry %s you can't add more than one like per posts!" % username  # noqa
                    self.render('likerror.html',
                                error=error,
                                p=post)
                else:
                    return self.render('likePost.html', p=post)

            # If there is no like, first like for the post
            else:
                return self.render('likePost.html', p=post)
        else:
            error = "Sorry %s you can't add like to your own posts!" % username
            self.render('likerror.html',
                        error=error,
                        p=post)

    def post(self, par):
        post_id = self.request.get('post_id')
        like_confirm = self.request.get('like_confirm')
        posts = greetings = Post.all().order('-created')
        username = self.user.name
        if not self.user:
            return self.redirect('/login')
        if(like_confirm == "like_confirm"):
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return self.render("error404.html")
            authorPost = post.author
            username = self.user.name
            # YES ADD LIKE POST: not the post author
            likes = Likes.all()
            if likes.get():
                idlike = post_id+username
                likes_new = db.GqlQuery('SELECT * FROM Likes WHERE idlike = :1',  # noqa
                                         idlike)
                likes_new_average = post.likes_average
                # if (likes_new.get() and likes_new_average!=0):
                if (likes_new.get() and likes_new_average != 0):
                    error = "Sorry %s you can't add more than one like per posts!" % username  # noqa
                    self.render('likerror.html',
                                error=error,
                                p=post)
                else:
                    author_like = self.user.name
                    likes_average = 1
                    l = Likes(idlike=post_id+username,
                              author_like=author_like,
                              post_id=post_id,
                              likes_average=likes_average)
                    l.put()

                    post.likes += 1
                    post.likes_average += 1
                    post.put()
                    return self.render('likepostdone.html')
            # If there is no like, first like for the post
            else:
                author_like = self.user.name
                likes_average = 1
                l = Likes(idlike=post_id+username, author_like=author_like,
                          post_id=post_id,
                          likes_average=likes_average)
                l.put()
                post.likes += 1
                post.likes_average += 1
                post.put()
                return self.render('likepostdone.html')


# this handler class manages the single post page, it renders to
# permalink.html which renders to post.html that contains the button
# edit to edit a post
class PostPage(BlogHandler):
    # the post_id parameter is taken from the url because it is a get!
    # instead the post parameters can be taken with:
    # self.request.get('<name-of-the-input-form>')
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return self.render("error404.html")
        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", username=self.user.name)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        # author = self.request.get('author')
        author = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error)


class EditComment(BlogHandler):

    def get(self, comment_id):
        if not self.user:
            return self.redirect('/login')

        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)
        id_post = c.id_post
        key = db.Key.from_path('Post', int(id_post), parent=blog_key())
        p = db.get(key)
        comments = Comment.all()
        authorComment = c.author
        username = self.user.name
        # YES EDIT COMMENT: only the author can
        if(authorComment == username):
            self.render('editcomment.html',
                        c=c)
        # NO EDIT COMMENT: only the author can
        else:
            error = "Sorry %s you can only edit your own comments!" % username
            self.render('editcommenterror.html',
                        p=p,
                        error=error)

    def post(self, par):
        username = self.user.name
        comment_edited = self.request.get('comment_edited')
        content_new_comment = self.request.get('content_new_comment')
        comment_id_new_comment = self.request.get('comment_id_new_comment')
        comment_id = self.request.get('comment_id')
        posts = greetings = Post.all().order('-created')
        comments = Comment.all()
        if not self.user:
            return self.redirect('/login')
        if(comment_edited == "zero"):
            key = db.Key.from_path('Comment', int(comment_id_new_comment))
            c = db.get(key)
            if c:
                authorComment = c.author
                if(content_new_comment):
                    key = db.Key.from_path('Comment',
                                           int(comment_id_new_comment))
                    c = db.get(key)
                    c.content = content_new_comment
                    c.put()
                    self.redirect('/blog/?')
                else:
                    error = "comment content please!"
                    comments = Comment.all()
                    self.render('editcomment.html', c=c, error=error)
            else:
                self.error(404)
                return self.render("error404.html")


class DeleteComment(BlogHandler):

    def get(self, comment_id):
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Comment', int(comment_id))
        c = db.get(key)
        comments = Comment.all()
        id_post = c.id_post
        key = db.Key.from_path('Post', int(id_post), parent=blog_key())
        p = db.get(key)
        authorComment = c.author
        username = self.user.name
        # YES DEL COMMENT: only the author can
        if(authorComment == username):
            self.render('deletecomment.html',
                        c=c)
        # NO DEL COMMENT: only the author can
        else:
            error = "Sorry %s you can only delete your own comments!" % username  # noqa
            self.render('deletecommenterror.html',
                        error=error,
                        p=p)

    def post(self, par):
        username = self.user.name
        delete_confirm = self.request.get('delete_confirm')
        comment_id_del = self.request.get('comment_id_del')
        if not self.user:
            return self.redirect('/login')
        if(delete_confirm == "delete_confirm"):
            key = db.Key.from_path('Comment', int(comment_id_del))
            c = db.get(key)
            if c:
                authorComment = c.author
                db.delete(c)
                return self.render('deletedone.html')
            else:
                self.error(404)
                return self.render("error404.html")


# Accounts and Security
# - Users are able to create accounts, login, and logout
# - Existing users can revisit the site and log back in without
# having to recreate their accounts each time.
# -Usernames are unique. Attempting to create a duplicate user
# results in an error message.
# -Stored passwords are hashed. Passwords are appropriately
# checked during login. User cookie is set securely.

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# overwrites the function done - used if the username is passed in
# the url (get)
# class Unit2Signup(Signup):
#     def done(self):
#         self.redirect('/unit2/welcome?username=' + self.username)
# inherits from the class Signup
# overwrites the function done
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            # sets cookie
            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        # the user inserts his username and password in the login-form
        username = self.request.get('username')
        password = self.request.get('password')
        # User login (checks val password)
        u = User.login(username, password)
        if u:
            # Blog Handler login (sets cookie)
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


# unlike the class Welcome, the username is in a cookie
class Welcome(BlogHandler):
    def get(self):
        # self user is set in the initialize function for eah request,
        # that reads the cookie, checks it is valid and sets the user in the
        # blogHandler that here is inherited
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/likepost/([0-9]+)', LikePost),
                               ('/editpost/([0-9]+)', EditPost),
                               ('/editcomment/([0-9]+)', EditComment),
                               ('/deletecomment/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)

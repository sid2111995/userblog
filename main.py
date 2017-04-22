import os
import re
import random
import hashlib
import hmac
from string import letters
import time
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Base(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def render_str(self, template, **param):
        param['user'] = self.username
        return render_str(template, **param)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class signup(Base):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        er = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "invalid username!"
            er = True
        if not valid_password(self.password):
            params['error_password'] = "Invalid password!"
            er = True
        elif self.password != self.verify:
            params['error_verify'] = "No match!"
            er = True
        if not valid_email(self.email):
            params['error_email'] = "not a valid email!"
            er = True
        if er:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(signup):
    def done(self):
        user = User.by_name(self.username)
        if user:
            msg = 'Sorry User already exists!'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')


class Welcome(Base):
    def get(self):

        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/register')


class Login(Base):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            msg = "Invalid login"
            self.render('login-form.html', error=msg)


class Logout(Base):
    def get(self):
        self.logout()
        self.redirect('/logoutsucc')


class Like(db.Model):
    uid = db.StringProperty(required=True)
    pid = db.StringProperty(required=True)

    @classmethod
    def count(cls, pi, ui):
        key = Like.all().filter("uid = ", ui).filter("pid = ", pi)
        return key.count()

    @classmethod
    def countLike(cls, pi):
        key = Like.all().filter("pid = ", pi)
        return key.count()


class Unlike(db.Model):
    uid = db.StringProperty(required=True)
    pid = db.StringProperty(required=True)

    @classmethod
    def count(cls, pi, ui):
        key = Unlike.all().filter("uid = ", ui).filter("pid = ", pi)
        return key.count()

    @classmethod
    def countLike(cls, pi):
        key = Unlike.all().filter("pid = ", pi)
        return key.count()


class Post(db.Model):

    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    user_id = db.StringProperty(required=True)
    create = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):

    text = db.TextProperty(required=True)
    uid = db.StringProperty(required=True)
    pid = db.StringProperty(required=True)
    uname = db.StringProperty(required=True)
    time = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def com(cls, pid):
        c = Comment.all().filter("pid = ", pid)
        return c


class MainHandler(Base):
    def render_front(self):
        post = db.GqlQuery(
            "select * from Post order by create desc limit 10")
        self.render('blog.html', post=post)

    def get(self):
        self.render_front()


class NewPost(Base):

    def get(self):
        if self.user:
            self.render('login.html')
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')
        title = self.request.get("title")
        art = self.request.get("art")
        error = ""

        if not title or not art:
                self.render(
                    'login.html',
                    title=title,
                    art=art,
                    error="Please add Both title and art and submit")

        else:
            obj = Post(
                title=title,
                art=art,
                user_id=str(self.user.key().id()))
            obj.put()
            self.redirect("/%s" % obj.key().id())


class latest(Base):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        self.render(
            'singlepost.html',
            post=post,
            countLikes=countLikes,
            countUnlikes=countUnlikes,
            comment_get=comment_get)

    def post(self, id):

        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))

        comment_get = Comment.com(str(post.key().id()))
        if self.request.get("delete"):
            if self.user and (post.user_id == str(self.user.key().id())):
                post.delete()
                time.sleep(0.1)
                self.redirect('/blog')
            else:
                self.render(
                    'singlepost.html',
                    post=post,
                    error="You cant edit this post",
                    countLikes=countLikes,
                    countUnlikes=countUnlikes,
                    comment_get=comment_get)

        if(self.request.get('edit')):
            if not self.user:
                self.redirect('/login')
            if self.user and post.user_id == str(self.user.key().id()):
                self.redirect('/edit/%s' % post.key().id())
            else:
                self.render(
                    "singlepost.html",
                    post=post,
                    error="You cant Edit this Post!!",
                    countLikes=countLikes,
                    countUnlikes=countUnlikes,
                    comment_get=comment_get)

        if (self.request.get('like')):
            if not self.user:
                self.redirect("/login")

            elif post.user_id == str(self.user.key().id()):
                self.render(
                    "singlepost.html",
                    post=post,
                    error="Cant like your own post!",
                    countLikes=countLikes,
                    countUnlikes=countUnlikes,
                    comment_get=comment_get)

            else:
                if Like.count(
                    str(post.key().id()),
                    str(
                        self.user.key().id())) >= 1:

                    self.render(
                        "singlepost.html",
                        post=post,
                        error="Cant like your this post again!",
                        countLikes=countLikes,
                        countUnlikes=countUnlikes,
                        comment_get=comment_get)
                else:
                    obj = Like(
                        pid=str(post.key().id()),
                        uid=str(
                            self.user.key().id()))
                    obj.put()
                    time.sleep(0.1)
                    self.redirect("/%s" % post.key().id())

        if (self.request.get('unlike')):
            if not self.user:
                self.redirect("/login")

            elif post.user_id == str(self.user.key().id()):
                self.render(
                    "singlepost.html",
                    post=post,
                    error="Cant unlike your own post!",
                    countLikes=countLikes,
                    countUnlikes=countUnlikes,
                    comment_get=comment_get)

            else:
                if Unlike.count(
                    str(post.key().id()),
                    str(
                        self.user.key().id())) == 1:

                    self.render(
                        "singlepost.html",
                        post=post,
                        error="Cant unlike your this post again!",
                        countLikes=countLikes,
                        countUnlikes=countUnlikes,
                        comment_get=comment_get)
                else:
                    obj = Unlike(
                        pid=str(post.key().id()),
                        uid=str(
                            self.user.key().id()))
                    obj.put()
                    time.sleep(0.1)
                    self.redirect("/%s" % post.key().id())

        if (self.request.get('comment')):
            if not self.user:
                self.redirect('/login')
            else:
                comment = self.request.get("commentbox")
                if not comment:
                    self.render(
                        "singlepost.html",
                        post=post,
                        error="Cant submit a blank comment!",
                        countLikes=countLikes,
                        countUnlikes=countUnlikes,
                        comment_get=comment_get)
                else:
                    obj = Comment(
                        text=comment,
                        uid=str(self.user.key().id()),
                        pid=str(post.key().id()),
                        uname=str(self.user.name))
                    obj.put()
                    time.sleep(0.1)
                    self.redirect("/%s" % post.key().id())


class Edit_comment(Base):

    def get(self, id):
        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        key = db.Key.from_path('Post', int(comment.pid))
        post = db.get(key)
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        if self.user and comment.uid == str(self.user.key().id()):
            self.render(
                "editc.html",
                comment=comment)
        else:
            self.render(
                "singlepost.html",
                post=post,
                error="You cant Edit this comment!!",
                countLikes=countLikes,
                countUnlikes=countUnlikes,
                comment_get=comment_get)

    def post(self, id):

        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        if not comment:
            return self.redirect('/login')
        newcomment = self.request.get('edcom')
        if self.user and comment.uid == str(self.user.key().id()):
            comment.text = newcomment
            comment.put()
            time.sleep(0.1)
            self.redirect("/%s" % comment.pid)

        else:
            self.render(
                "editc.html",
                comment=comment,
                error="Cant submit blank!!")


class Delete_comment(Base):

    def get(self, id):
        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        key = db.Key.from_path('Post', int(comment.pid))
        post = db.get(key)
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        if self.user and comment.uid == str(self.user.key().id()):
            self.render("deletec.html", comment=comment)

        else:
            self.render(
                "singlepost.html",
                post=post,
                error="You cant delete this comment!!",
                countLikes=countLikes,
                countUnlikes=countUnlikes,
                comment_get=comment_get)

    def post(self, id):

        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        if not comment:
            return self.redirect('/login')
        newcomment = self.request.get('edcom')
        if self.user and comment.uid == str(self.user.key().id()):
            comment.delete()
            time.sleep(0.1)
            self.redirect("/%s" % comment.pid)
        else:
            self.render(
                "deletec.html",
                comment=comment,
                error="Cant submit blank!!")


class Edit(Base):

    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        self.render('edit.html', post=post)

    def post(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        title = self.request.get("title")
        art = self.request.get("art")
        if self.request.get('cancel'):
            return self.redirect("/%s" % post.key().id())

        if self.user and (
            post.user_id == str(
                self.user.key().id())) and title and art:
            post.title = title
            post.art = art
            post.put()
            time.sleep(0.1)
            self.redirect("/%s" % post.key().id())
        else:
            self.render(
                'edit.html',
                post=post,
                error="User cant submit blank!!")


class Start(Base):

    def get(self):
        self.redirect('/blog')


class Logoutsucc(Base):

    def get(self):
        self.render("logoutsucc.html")


app = webapp2.WSGIApplication([
    ('/', Start),
    ('/signup', signup),
    ('/welcome', Welcome),
    ('/register', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog', MainHandler),
    ('/newpost', NewPost),
    ('/([0-9]+)', latest),
    ('/edit/([0-9]+)', Edit),
    ('/deletec/([0-9]+)', Delete_comment),
    ('/editc/([0-9]+)', Edit_comment),
    ('/logoutsucc', Logoutsucc)

], debug=True)

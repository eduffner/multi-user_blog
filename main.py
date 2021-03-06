# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import re
import random
import hashlib
import hmac
from string import letters

import jinja2
import webapp2

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'secret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        # bid = self.read_secure_cookie('blog_id')
        # self.blog = 

    # def set_blog(self, blog):
    #     self.set_secure_cookie('blog_id', str(blog.key.id()))

    # def exit_blog(self, blog):
    #     self.response.headers.add_header('Set-Cookie', 'blog_id=; Path=/')


def blog_key(name = 'default'):
        return ndb.Key('Blog', name)
## Blog
class Blog(ndb.Model):
    title = ndb.StringProperty(required = True)
    user = ndb.StringProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)

    def render(self):
        return render_str("blog.html", blog=self, user=self.user)

class BlogPage(BlogHandler):
    def get(self, blog_id):
        entries = []
        
        blog = Blog.get_by_id(int(blog_id), parent=self.user.key)
       
        if not blog:
            self.render("error.html")
            return
        entries = Entry.query(ancestor=blog.key).fetch()
        self.render('blog_entries.html', blog=blog, user=self.user, entries=entries)


class NewBlog(BlogHandler):
    def render_form(self, title='', error=''):
        self.render("new_blog.html", title=title, error=error, user=self.user)

    def get(self, blog_id):
        if not self.user:
            self.render('login.html')

        if blog_id:
            key = ndb.Key('Blog', int(blog_id))
            blog = ndb.get(key)
            if blog:
                self.render_form(blog.title)
            else:
                self.render("error.html")
                return
        else:
            self.render_form()

    def post(self, blog_id):
        if not self.user:
            self.render('blog.html')


        title = self.request.get('title')

        if title:
            if blog_id:
                key = ndb.Key('Blog', int(blog_id))
                entry = ndb.get(key)
                if entry:
                    entry.title = title
            else:  
                blog = Blog(parent = self.user.key,
                            title = title,
                            user = self.user.name)
            blog.put()
            self.redirect('/blog/%s' % str(blog.key.id()))
        else:
            error = 'Both an Entry and Title are required'
            self.form(title, text, error)

class DeleteBlog(BlogHandler):
    def get(self, blog_id):
        key = ndb.Key('Blog', int(blog_id))
        blog = ndb.get(key)
        if not blog:
            self.render("error.html")
            return
        blog.delete()
        blogs = Blog.query().filter('user =', self.user.name).order('-created')
        self.render("user_blogs.html", user=self.user, blogs=blogs)

## Entry
class Entry(ndb.Model):
    title = ndb.StringProperty(required = True)
    text = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)

    def render(self, blog):
        self._render_text = self.text.replace('\n', '<br>')
        return render_str("entry.html", entry=self, blog=blog)


class NewEntry(BlogHandler):
    def render_form(self, blog='', title='', text='', error=''):
        self.render("new_entry.html", blog=blog, title=title, text=text, error=error, user=self.user)

    def get(self, *args, **kwargs):
        blog_id = kwargs['blog_id']
        entry_id = kwargs['entry_id']
        if not self.user:
            self.redirect('/login')
            return

        if blog_id:
            blog = Blog.get_by_id(int(blog_id), parent=self.user.key)
            
            if not blog:
                self.render("error.html", message="No blog Instance Found")
                return

        if entry_id:
            key = ndb.Key('Entry', int(entry_id), parent=blog_key)
            entry = ndb.get(key)

            if not entry:
                self.render("error.html", message="No entry Instance Found")
                return
            
            self.render_form(entry.title, entry.text, blog)
            
        else:
            self.render_form(blog)

    def post(self, *args, **kwargs):
        
        if not self.user:
            self.redirect('/blog')
            return

        title = self.request.get('title')
        text = self.request.get('text')

        if title and text:
            entry_id = kwargs['entry_id']
            blog_id = kwargs['blog_id']
            if blog_id: 
                b_key = blog_key(int(blog_id))
                if entry_id:
                    entry = ndb.get(key)
                    if entry:
                        entry.title = title
                        entry.text = text
           
                else:
                    blog = Blog.get_by_id(int(blog_id), parent=self.user.key)
                    entry = Entry(title=title, text=text, parent=blog.key)
            else:
                self.render("error.html")
                return

            entry.put()
            self.redirect('/%s/entry/%s' % (str(blog_id), str(entry.key.id()) ) )
        else:
            error = 'Both an Entry and Title are required'
            self.form(title, text, error)

class DeleteEntry(BlogHandler):
    def get(self, *args, **kwargs):
        entry_id = int(kwargs['entry_id'])
        blog_id = int(kwargs['blog_id'])
        blog_key = blog_key(blog_id)
        key = ndb.Key('Entry', int(entry_id), parent=blog_key)
        entry = ndb.get(key)
        if not entry:
            self.render("error.html")
            return
        entry.delete()
        self.render("blog_entries.html", user=self.user)

class EntryPage(BlogHandler):
    def get(self, *args, **kwargs):
        blog_id = kwargs['blog_id']

        blog = Blog.get_by_id(int(blog_id), parent=self.user.key)

        if not blog:
            self.render("error.html", message="No blog instance Found.")
            return
        
        entry_id = kwargs['entry_id']

        entry = Entry.get_by_id(int(entry_id), parent=blog.key)
        entries = []

        if not entry:
            self.render("error.html", message="No entry instance Found.")
            return

        entries.append(entry)
        self.render("blog_entries.html", entries=entries, user=self.user, blog=blog)

## Comment
class Comment(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add = True)
    user = ndb.StringProperty(required = True)

    def render(self):
        return render_str("entry.html", comment = self)

class NewComment(BlogHandler):
    def get():
        self.render("blog_entries.html", user=self.user)

## User
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        print("uid: %s" % uid)
        return User.get_by_id(uid, users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):   
            return u

class MainPage(BlogHandler):
    def get(self):
        
        if(self.user):
            
            blogs = Blog.query(parent=self.user.key).fetch()
            self.render('user_blogs.html', blogs=blogs, user=self.user)

        else:
            self.redirect('/login')

    def post(self):
        print('User: %s' % self.user)

class Rot13(BlogHandler):
    def get(self):
        self.render("rot13.html")

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')
        self.render("rot13.html", text=rot13)


class SignUp(BlogHandler):
    def get(self):
        self.render("sign_up.html")

    def post(self):
        has_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

        if not valid_username(self.username):
            has_error = True
            params['error_username'] = "This is not a valid username"

        if not valid_password(self.password):
            has_error = True
            params['error_password'] = "This is not a valid password"
        elif not self.password == self.verify:
            has_error = True
            params['error_verify'] = "Passwords don't match"
        
        if not valid_email(self.email):
            has_error = True
            params['error_email']= "This is not a valid email"

        if has_error:
            self.render("sign_up.html", **params)
        else:
            u = User.by_name(self.username)
            if u:
                msg = 'That user already exists.'
                self.render('sign_up.html', error_username = msg)
            else:
                u = User.register(self.username, self.password, self.email)
                u.put()

                self.login(u)
                self.redirect('/blogs')

class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        users = User.query()

        u = User.login(username, password)
        
        if u:
            self.login(u)
            self.redirect('/blogs')
            return
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout();
        self.redirect('/blogs');

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render("/welcome.html", user = self.user)
        else: 
            self.render("/login.html")

def render_icons(edit=False):
    if edit:
        self.render('edit.html')
    else:
        self.render('new.html')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

app = webapp2.WSGIApplication([
    ('/', Welcome),
    ('/blogs', MainPage),
    ('/blog/([0-9]+)', BlogPage),
    ('/blog/new/([0-9]+)?', NewBlog),
    ('/blog/delete/([0-9]+)', DeleteBlog),
    webapp2.Route('/<blog_id:([0-9]+)>/entry/<entry_id:([0-9]+)>', EntryPage), 
    webapp2.Route('/<blog_id:([0-9]+)>/entry/new/<entry_id:([0-9]+)?>', NewEntry),
    ('/entry/delete/([0-9]+)', DeleteEntry),
    ('/rot13', Rot13),
    ('/login', Login),
    ('/logout', Logout),
    ('/signup', SignUp),
    ('/welcome', Welcome)
], debug=True)

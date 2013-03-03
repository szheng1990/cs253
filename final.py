import os
import webapp2
import jinja2
import cgi
import re
import hashlib
import string
import random
import json
import logging
import time

from xml.dom import minidom
import urllib2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
  loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
      return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return "%s|%s" % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)


class Handler(webapp2.RequestHandler):
  #support function for rendering later
  def write(self,*a,**kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params) # built in? test later

  def render(self, template, **kw):
    self.write(self.render_str(template,**kw))


class Page(db.Model):
  pagename = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)

  @classmethod
  def has_page(cls, pagename):
    pages = Page.all()
    for page in pages:
      if page.pagename == pagename:
        return True
    return False


  @classmethod #return most recent page
  def most_recent_page(cls, pagename):
    page = Page.gql("WHERE pagename = :pagename ORDER BY created DESC", pagename=pagename).get()
    return page

class User(db.Model):
  username = db.StringProperty(required = True)
  pw_hash = db.StringProperty(required = True)
  created = db.DateTimeProperty(auto_now_add=True)

  @classmethod
  def has_name(cls, username):
    users = User.all()
    for user in users:
      if user.username == username:
        return True
    return False

#returns username if logged in
def logged_in(self):
    username = ""
    status = "no"
    uid_cookie_str = self.request.cookies.get('uid')
    if uid_cookie_str:
       uid = check_secure_val(uid_cookie_str)
       if uid and uid.isdigit():
          username = User.get_by_id(int(uid)).username
          status="yes"
    return status, username


class MainPage(Handler):
  def get(self):
    status, username = logged_in(self)
    message = "Welcome, Udacity!"
    if not Page.has_page('/'):
      page = Page(pagename='/',content=message)
      page.put()
    else:
      message = Page.most_recent_page('/').content
    
    self.render('wikiWelcome.html',message=message, status=status, username=username)


class Signup(Handler):
  def render_signup(self, username="", email="", ue = "", pe = "", ve = "", ee = ""):
    self.render("signup.html", username=username, email=email, ue=ue, pe=pe, ve=ve, ee=ee)

  def get(self):
    self.render_signup()

  def post(self):
    username = self.request.get("username")
    password = self.request.get("password")
    verify = self.request.get("verify")
    email = self.request.get("email")

    error = False

    params = {}

    u_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    p_re = re.compile(r"^.{3,20}$")
    e_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

    if not u_re.match(username):
       error = True
       params['username'] = username
       params['ue'] = "invalid username"

    if not p_re.match(password):
       error = True
       params['pe'] = "invalid password"

    if email and not e_re.match(email):
       error = True
       params['email'] = email
       params['ee'] = 'invalid email'

    if password != verify:
       error = True
       params['ve'] = 'password inputs do not match!'

    if error == True:
      self.render_signup(**params)

    if error == False:
      if User.has_name(username): #username already taken
         params['username'] = username
         params['email'] = email
         params['ue'] = "user already exist"
         self.render_signup(**params)
      else:
         #step1: put new user into database
         #step2: set cookie and redirect to welcome page
         pw_hash = make_pw_hash(username, password)
         newuser = User(username=username, pw_hash=pw_hash)
         newuser.put()

         uid = newuser.key().id()
         self.response.headers['Content-Type'] = 'text/plain'
         new_cookie_val = str(make_secure_val(str(uid)))
         self.response.headers.add_header('Set-Cookie', 'uid=%s; Path=/'  % new_cookie_val)

         self.redirect('/') # redirect to front page

class Login(Handler):
  def render_signin(self, ue = "", pe = ""):
    self.render("signin.html", ue=ue, pe=pe)

  def get(self):
    self.render_signin()

  def post(self):
    #step1: verify name+password combo
    #step2: set cookie and redirect to welcome page
    username = self.request.get('username')
    password = self.request.get('password')
    
    if User.has_name(username):
      user = User.gql("WHERE username = :username", username=username).get()
      h = user.pw_hash
      if valid_pw(username, password, h):
         #logged in and set cookie
         uid = user.key().id()
         self.response.headers['Content-Type'] = 'text/plain'
         new_cookie_val = str(make_secure_val(str(uid)))
         self.response.headers.add_header('Set-Cookie', 'uid=%s; Path=/'  % new_cookie_val)
         #redirect to welcome page
         self.redirect('/')

      else:
         self.render_signin(pe='invalid password')
    else:
      self.render_signin(ue='invalid username')


class Logout(Handler):
  def get(self):
    self.response.set_cookie('uid',"")
    self.redirect('/')

class MainEditPage(Handler):
  def get(self):
    # check logged in status, redirect if needed
    status, username = logged_in(self)
    if status == "no":
      self.redirect('/')

    content = Page.most_recent_page('/').content
    self.render('edit.html',content=content)

  def post(self):
    content = self.request.get('content')
    if content:
      newPage = Page(pagename='/',content=self.request.get('content'))
      newPage.put()
      self.redirect('/')

    else:
      error = "Please fill in content!"
      self.render('edit.html', content="", error=error)



class OtherEditPage(Handler):
  def get(self, pagename):
    # first, check login, redirect as neccesary
    status, username = logged_in(self)
    if status == "no":
      self.redirect('/%s' % pagename)

    content = ""
    if Page.has_page(pagename):
         content = Page.most_recent_page(pagename).content
    self.render('edit.html',content=content)

  def post(self, pagename):
    content = self.request.get("content")

    if content:
      #insert into database Blog
      newPage = Page(pagename=pagename,content=content)
      newPage.put()

      self.redirect('/%s' % pagename)
    else:
      error = "Please fill in content!"
      self.render('edit.html', content="", error=error)
    # if both fields are filled, redirect to /blog/id
    # else, reload new.html with error message

class MainHistoryPage(Handler):
  def get(self):
    pages = Page.gql("WHERE pagename='/' ORDER BY created DESC")
    self.render('history.html',pages=pages, pagename="")

class OtherHistoryPage(Handler):
  def get(self, pagename):
    pages = Page.gql("WHERE pagename=:pagename ORDER BY created DESC", pagename=pagename)
    self.render('history.html',pages=pages, pagename='/'+pagename)

class WikiPage(Handler):
  def get(self, pagename):
    message = None
    status, username = logged_in(self)
    if Page.has_page(pagename):
       message = Page.most_recent_page(pagename).content
       self.render('wikiPage.html',pagename=pagename, message=message, status=status, username=username)
    else:
      if status == "yes":
         self.redirect('/_edit/%s' % pagename)
      else:
         self.write("""
          This page hasn't been created yet, please <a href="../login">login</a> to created the first version:)
          """)
    





PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit', MainEditPage), 
                               ('/_edit/([a-zA-Z0-9_-]+)', OtherEditPage),
                               ('/_history', MainHistoryPage), 
                               ('/_history/([a-zA-Z0-9_-]+)', OtherHistoryPage),
                               ('/([a-zA-Z0-9_-]+)', WikiPage),
                               ],
                              debug=True)
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

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
  url = IP_URL+ip 
  content = None
  try:
     content = urllib2.urlopen(url).read()
  except URLError:
    return

  if content:
    d = minidom.parseString(content)
    coords = d.getElementsByTagName("gml.coordinates")
    if coords and coords[0].firstChild.nodeValue:
      lon, lat = coords[0].firstChild.nodeValue.split(',')
      return db.GeoPt(lat, lon)


class Handler(webapp2.RequestHandler):
  #support function for rendering later
  def write(self,*a,**kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params) # built in? test later

  def render(self, template, **kw):
    self.write(self.render_str(template,**kw))

class Blog(db.Model):
  subject = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  coords = db.GeoPtProperty() # not required

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


class MainPage(Handler):
  def get(self):
    splash = """
                <a href="../blog/signup">Sign Up</a>
                <br>
                <a href="../blog/login">Sign In</a>
             """
    self.response.out.write(splash)

class SignUpPage(Handler):
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

         self.redirect('/blog/welcome') # redirect to front page

class SignInPage(Handler):
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
         self.redirect('/blog/welcome')

      else:
         self.render_signin(pe='invalid password')
    else:
      self.render_signin(ue='invalid username')

class WelcomePage(Handler):
  def get(self):
    uid_cookie_str = self.request.cookies.get('uid')
    uid = check_secure_val(uid_cookie_str)
    if uid and uid.isdigit():
      username = User.get_by_id(int(uid)).username
      self.write("Welcome, %s!" % username)
    else:
      self.redirect('/signup')

class LogoutHandler(Handler):
  def get(self):
    self.response.set_cookie('uid',"")
    self.redirect('/blog/signup')

CACHE = {}
def top_blogs(update = False):
  #logging.error("DB QUERY")
  key = 'top'
  if not update and key in CACHE:
    return CACHE[key]
  else:
     logging.error("DB QUERY")
     blogs = db.GqlQuery("SELECT * FROM Blog order by created desc limit 10")
     blogs = list(blogs)
     CACHE[key] = blogs
     return blogs

MCACHE = {}
class FrontPage(Handler):
  def get(self):
    elapsed = None
    if not 'time' in MCACHE:
      MCACHE['time'] = time.time()
      elapsed = 0 #first query
    else:
      elapsed = time.time() - MCACHE['time']

    query_info = "Queried %f seconds ago" % elapsed

    blogs = top_blogs()
    self.render("front.html", blogs=blogs, query_info = query_info) # front page displaying all articles

class FrontJsonPage(Handler):
  def get(self):
    blogs = db.GqlQuery("SELECT * FROM Blog order by created desc limit 10")
    blogs = list(blogs)
    self.response.headers['Content-Type'] = 'application/json'
    output = [dict([('content',blog.content),('subject',blog.subject)]) for blog in blogs]
    self.write(json.dumps(output))

class NewPost(Handler):
  def render_new(self, subject="", content="", error = ""):
    self.render("new.html", subject=subject, content=content, error=error)
  
  def get(self):
    self.render_new()

  def post(self):
    subject = self.request.get("subject")
    content = self.request.get("content")

    if subject and content:
      #insert into database Blog
      b = Blog(subject=subject, content=content)
      b.put()

      #clear cache
      top_blogs(True)
      self.redirect('/blog/%s' % b.key().id())
    else:
      error = "Please fill in both title and content!"
      self.render_new(subject, content, error)
    # if both fields are filled, redirect to /blog/id
    # else, reload new.html with error message

class ResetPage(Handler):
  def get(self):
    db.delete(db.Query(Blog))
    self.redirect('/blog')

ECACHE = {}
class EntryPage(Handler):
  def get(self, entry_id):
    elapsed = None
    if not entry_id in ECACHE:
      ECACHE[entry_id] = time.time()
      elapsed = 0 #first query
    else:
      elapsed = time.time() - ECACHE[entry_id]

    query_info = "Queried %f seconds ago" % elapsed
    entry = Blog.get_by_id(int(entry_id))
    self.render("entry.html", subject=entry.subject, content=entry.content, query_info=query_info)

class EntryJsonPage(Handler):
  def get(self, entry_id):
    entry = Blog.get_by_id(int(entry_id))
    self.response.headers['Content-Type'] = 'application/json'
    pre_json = dict([('content',entry.content),('subject', entry.subject)])
    self.write(json.dumps(pre_json))

class FlushHandler(Handler):
  def get(self):
    #CACHE.clear()
    MCACHE.clear()
    ECACHE.clear()
    self.redirect('/blog')


application = webapp2.WSGIApplication([
  ('/', MainPage),
  ('/blog', FrontPage),
  ('/blog/.json', FrontJsonPage),
  ('/blog/signup', SignUpPage),
  ('/blog/login', SignInPage),
  ('/blog/logout', LogoutHandler),
  ('/blog/flush', FlushHandler),
  ('/blog/welcome', WelcomePage),
  ('/blog/newpost', NewPost),
  ('/blog/reset', ResetPage),
  ('/blog/([0-9]+)', EntryPage),
  ('/blog/([0-9]+).json', EntryJsonPage)], 
  debug = True)
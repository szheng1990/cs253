import os
import webapp2
import jinja2
import cgi

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
  loader = jinja2.FileSystemLoader(template_dir)
  autoescape = True)

entryName = str()
entryContent = str()

class Handler(webapp2.RequestHandler):
  #support function for rendering later
  def write(self.*a,**kw):
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

class StartPage(Handler):
  def get(self):
    self.redirect('/blog')


class FrontPage(Handler):

  def get(self):
    blogs = db.GqlQuery("SELECT * FROM Blog order by created desc")
    self.render("front.html") # front page displaying all articles

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
      entryName = subject #global variable
      entryContent = content #global variable
      self.redirect('/blog/%s' % entryName)

    else:
      error = "Please fill in both title and content!"
      render_new(subject, content, error)
    # if both fields are filled, redirect to /blog/id
    # else, reload new.html with error message

class EntryPage(Handler):
  def get(self):
    self.render("entry.html", subject=entryName, content=entryContent)

app = webapp2.WSGIAplication([
  ('/', StartPage)
  ('/blog', FrontPage),
  ('/blog/new', NewPost),
  ('/blog/%s' % entryName, EntryPage)], 
  debug = True)
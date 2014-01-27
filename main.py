#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#

import os
import re
from string import letters
import cgi
import webapp2
import jinja2
from google.appengine.ext import db
import hashlib
import random
import string
import hmac
import urllib2
from xml.dom import minidom
import json
import time
import datetime
import urllib2
from urllib2 import Request, urlopen, URLError
from google.appengine.api import images
import cgi
import urllib
import wsgiref.handlers
import logging
from google.appengine.ext import db
from google.appengine.api import images
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import images
from google.appengine.api import memcache


DEBUG = os.environ['SERVER_SOFTWARE'].startswith('Development')

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	def render_str(self,template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

art_key = db.Key.from_path('ASCIIChan', 'arts')
def console(s):
    sys.stderr.write('%s\n' % s)

blog_key = db.Key.from_path('blog', 'blog')

def console(s):
    sys.stderr.write('%s\n' % s)

class Art(db.Model):
    title= db.StringProperty(required = True)
    art= db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add=True)
    coords = db.GeoPtProperty()

class Blog(db.Model):
    subject = db.StringProperty(required= True)
    content= db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)
    by = db.StringProperty()
    category = db.StringProperty()
    
    def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p=self)

class Users(db.Model):
	user = db.StringProperty(required=True)
	passw = db.StringProperty(required=True)
	email = db.StringProperty()
	avatar = db.BlobProperty()

def user_key(user_name=None):
	return db.Key.from_path('Users', key_name or 'default_user')


class Greeting(db.Model):
    author = db.UserProperty()
    content = db.StringProperty(multiline=True)
    avatar = db.BlobProperty()
    date = db.DateTimeProperty(auto_now_add=True)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']
month_abbvs = dict((m[:3].lower(), m) for m in months)

def valid_month(month):
    if month:
        short_month=month[:3].lower()
        return month_abbvs.get(short_month)

def valid_day(day):
    if day and day.isdigit():
        day = int(day)
        if day > 0 and day <= 31:
            return day

def valid_year(year):
    if year and year.isdigit():
        year = int(year)
        if year > 1900 and year <= 2020:
            return year

def escape_html(s):
    for(i,o) in (("&", "&amp;"),
                 (">", "&gt;"),
                 ("<", "&lt;"),
                 ('"', "&quot;")):
        s = s.replace(i,o)
    return s

def escape(s):
    return cgi.escape(s, quote = True);

def rot13encrypt(text):
	return text.encode("rot13")
	
SECRET = "iamsosecret"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
QUERIED = re.compile("(?i)Queried\s+(\d+)(\.\d+)?\s+seconds?\s+ago")

def valid_username(username):
	return username and USER_RE.match(username)

def valid_password(password):
	return password and PASSWORD_RE.match(password)

def valid_email(email):
	return not email or EMAIL_RE.match(email)

def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

def make_salt():
	return "".join(random.choice(string.letters) for x in xrange(5))
	
def make_pw_hash(name,pw, salt= None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw+ salt).hexdigest()
	return "%s,%s" % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	return h == make_pw_hash(name, pw, salt)

COOKIE_RE = re.compile(r'.+=; Path=/')
def valid_cookie(cookie):
	return cookie and COOKIE_RE.match(cookie)	


"""IP_URL="http://api.hostip.info/?ip="
def get_coords(ip):
    #ip="4.2.2.2"
    #ip="23.24.209.141"
    url=IP_URL+ip
    content = None
    try:
        content=urllib2.urlopen(url).read()
    except URLError:
        return
    if content:
        d=minidom.parseString(content)
        coords= d.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon,lat= coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat,lon)


GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
	markers = '&'.join('markers=%s,%s' % (p.lat, p.lon)
				for  p in points)
	return GMAPS_URL+markers"""
	
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
	markers ='&'.join('markers= %s, %s' % (p.lat, p.lon)
						for p in points)
	return GMAPS_URL + markers

IP_URL = "http://api.hostip.info/?ip=?"
def get_coords(ip):
	#ip = "4.2.2.2"
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except urllib2.URLError:
		return
	if content:
	    #parse coordinates here
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
			lon, lat = coords[0].childNodes[0].nodeValue.split(',')
			return db.Geopt(lat, lon)

def json_parser(query_obj):
	result = []
	for entry in query_obj:
		result.append(dict([(p, unicode(getattr(entry,p))) for p in entry.properties()]))
	return result

def top_arts(update = False):
    key = 'top'
    arts = memcache.get(key)
    if arts is None or update:
#    if not update and key in CACHE:
#        arts = CACHE[key]
#    else:
        logging.error("DB QUERY")
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")

        #prevent running multiple queries
        arts = list(arts)
        memcache.set(key, arts)
#        CACHE[key] = arts
    return arts

def blog_cache(update = False):
	bkey = 'blog'
	blogs = memcache.get(bkey)
	time_key ='blogkey'
	if blogs  is None or update:
	    logging.error("DB QUERY")
	    blogs= db.GqlQuery("SELECT * "
			       "FROM Blog"
				" ORDER BY created DESC limit 10")
	    blogs = list(blogs)
	    memcache.set(bkey, blogs)
	    memcache.set(str(time_key), (time.time()))
	age = time.time() - memcache.get(str(time_key))
	timecache ="%f" % age
	return blogs,timecache

def post_cache(blog_id, update= False):
    permacache = blog_id
    pkey= permacache
    posts = memcache.get(pkey)
    post_time_key ='plkey'
    times = memcache.get(post_time_key)
    if posts  is None or update==True:
       logging.error("DB QUERY")
       posts= Blog.get_by_id(int(blog_id))
       #posts = list(posts)
       memcache.set(pkey, posts)
       memcache.set(str(post_time_key), (time.time()))
    age = time.time() - memcache.get(post_time_key)
    timecache ="%f" % age
    return posts, timecache

    

form="""
    <form method="post">
    What is your birthday?
    <br>
    <label>Month
    <input type="text" name="month" value="%(month)s">
    </label>
    <label>Day
    <input type="text" name="day" value="%(day)s">
    </label>
    <label>Year
    <input type="text" name="year" value="%(year)s">
    </label>
    <br>
    <div style="color: red">%(error)s</div>
    <br>
    <input type="submit">
    <br>
    <br><a href="/">Home</a>
</form>
"""
main="""
<H1>Hi, it's Thaman Chand CS253 course home page</H1>
<br>
<br>
<label>
<a href="/formvalidation">Form Validation</a><br>
</label>
<label>
<a href="/ROT13">ROT13 exercise</a><br>
</label>
<a href="/blog/signup">Singup Exercise</a><br>
<a href="/ASCII">ASCII Exercise</a><br>
<a href="/blog">Blog</a><br>
</label>
"""

textarea="""
<H2>Enter some text to ROT13:</H2>
  <form method="post">
      <textarea name="text"
                style="height: 100px; width: 400px;">%(name)s</textarea>
      <br>
      <input type="submit">
    </form>
<br>
<a href="/">Home</a>

"""
class IndexPage(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(main)

class Form(webapp2.RequestHandler):
    def write_form(self,error="", month="", day="", year=""):
        self.response.out.write(form % {"error":error, "month":escape_html(month),
        "day":escape_html(day), "year":escape_html(year)})

    def get(self):
        self.write_form()

    def post(self):

        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_form("That doesn't look valide to me, friend", user_month,
                            user_day, user_year)
        else:
            self.redirect("/form/thanks")

class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Thanks! That's a totally valid day!")

class ROT13(webapp2.RequestHandler):
	def textarea_write(self,name=''):
		self.response.out.write(textarea %{'name':name})
	def get(self):
		self.textarea_write()

	def post(self):
		txt= self.request.get('text')
		rot13text= rot13encrypt(txt)
		self.textarea_write(escape(rot13text))


class Signup(BaseHandler):
	def get(self):
		self.render("Signup.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		params = dict(username = username,
		                      email = email)

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
		   	have_error = True

		if not valid_password(password):
		  	params['error_password'] = "That wasn't a valid password."
		   	have_error = True

		elif password != verify:
		  	params['error_verify'] = "Your passwords didn't match."
		   	have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
		  	have_error = True

		if have_error:
			self.render('Signup.html', **params)
		else:
			self.redirect('/Signup/Welcome?username=' + username)
			
class Login(BaseHandler):
	def get(self):
		self.render("login.html")
	def post(self):
		
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		params = dict(username = username)

		hash_p = make_pw_hash(username,password)
		user_exist = Users.all().filter('user =', username).get()
		
		if not username:
			params["error_username"] = "Username can't be blank!"
			have_error = True
		if not password:
			params["error_password"] = "Password can't be blank!"
			have_error = True
		elif  not user_exist:
			params['error_invalid'] ="Not a valid username"
			have_error = True
		else:
			h = user_exist.passw
			if not valid_pw(username,password, h):
				params['error_invalid'] ="Invalid password"
				have_error = True
	
		if have_error:
			self.render('login.html', **params)
		
		else:
			user_id = user_exist.key().id()
			user_cookie = make_secure_val(str(user_id))
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % user_cookie)
			self.redirect('/blog/welcome')
			#self.redirect('/blog/login/welcome?username=' + username)

class newuser(BaseHandler):
	def get(self):
		self.render("Signup.html")

	def post(self):
		have_error = False
		username = self.request.get(escape('username'))
		password = self.request.get(escape('password'))
		hash_p = make_pw_hash(username, password)
		verify = self.request.get(escape('verify'))
		email = self.request.get(escape('email'))
		avatar = self.request.get('img')
		

		params = dict(username = username,
		                      email = email)
		#user_info = Users.gql("WHERE username= :1", username)

		#if Users.all().filter('username=', username).get():
		#	have_error = True
		#	params['error_exist'] = "Username already taken!"
		user_exist = Users.all().filter('user =', username).get()
		if user_exist:
			params['error_exist'] = "Username already taken!"
			have_error = True
		   	
		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
		   	have_error = True

		if not valid_password(password):
		  	params['error_password'] = "That wasn't a valid password."
		   	have_error = True

		elif password != verify:
		  	params['error_verify'] = "Your passwords didn't match."
		   	have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
		  	have_error = True

		if have_error:
			self.render('Signup.html', **params)
		else:
			userinfo = Users(user = username, passw= hash_p, email=email)
			avatar = self.request.get('img')
			#avatar = request.FILES['img'].read()
			
			if avatar:
				image = self.request.get('img')
				userinfo.avatar = db.Blob(images.resize(image,48, 48))
				import logging
				logging.info('persisted')
				#mime = self.request.POST['img'].type
				#mime = mime.split('/')
				#icon_image = db.Blob(images.resize(avatar, 90,90))
				#prof.avatar = db.Blob(icon_image)
				#icon_image = db.Blob(images.resize(avatar, 75, 75))
				#userinfo.avatar = db.Blob(icon_image)
				#if mime[1] == 'jpeg' or 'jpg' or 'gif' or 'png':
				#	userinfo.put()
				#userinfo.avatar = avatar
				#userinfo.avatar = db.Blob(urlfetch.Fetch(avatar_url).avatar)
			userinfo.put()
			user_id = userinfo.key().id()
			user_cookie = make_secure_val(str(user_id))
			#uinfo = self.request.POST['userinfo'].type
			#self.response.headers('infokey=%s' % userinfo)
			self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % user_cookie)
			#self.response.headers['Content-Type'] = "image/jpeg"
			#self.redirect('/blog/login/welcome?username=' + username)
			self.redirect('/blog/welcome')
class disp_image(webapp.RequestHandler):
	def get(self):
		key = self.request.get('key')
		image = Users.get(key)
		if image:
		    self.response.headers['Content-Type'] = "image/png"
		    return self.response.out.write(image.avatar)
		else:
		    self.response.headers['Content-Type'] = "image/png"
		    return self.response.out.write("/static/unknown.gif")
class Welcome(BaseHandler):
	def get(self):
		user_id = self.request.cookies.get('user_id')
		uinfo = "ahBkZXZ-dGhhbWFuLWNzMjUzcgsLEgVVc2VycxgNDA"
		if user_id:
			parts = user_id.split('|')
			real_id = parts[0]
			hash2 = parts[1]
			if user_id == make_secure_val(real_id):
				a = int(real_id)
				user = Users.get_by_id(a)
				user_key = user.key()
				blogrec= db.GqlQuery("SELECT * from Blog"
				" ORDER BY created DESC limit 10")
				self.render('welcome.html', username = user.user, avatar = user_key, blog=blogrec)
			else:
				self.redirect('/blog/signup')
		else:
			self.redirect('/blog/signup')

class logout(BaseHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect('/blog/signup')

class ASCII(Handler):
    def render_front(self, title="", art="", error=""):
        farts = top_arts()

        #find arts with coords, if any display image url
        points = []
        points = filter(None, (a.coords for a in farts))

        img_url = None
        if points:
            img_url = gmaps_img(points)

        self.render("ascii.html", title=title,
                     art=art, error = error, farts = farts, img_url=img_url)

    def get(self):
        #self.write(self.request.remote_addr)
        #self.write(repr(get_coords(self.request.remote_addr)))#-ON NET
        return self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art(title = title, art = art)
            # look up users' coordinates, add them to the art

            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords = coords

            a.put()
            #CACHE.clear() # == CACHE['top'] = None#
            top_arts(True)

            self.redirect("/ASCII")
        else:
            error = "we need both a title and some artwork!"
            self.render_front(title, art, error)

class BLOG(BaseHandler):
    def write_blog(self):
	blogs, timecache= blog_cache()
	#newno = self.request.get('numpost')
	#if newno:
	#    numpost = int(newno)
	#    query= db.GqlQuery("SELECT * from Blog"
	#    " ORDER BY created DESC")
	#    blogrec = query.fetch(limit=numpost)
	#    self.render("blog.html", blog=blogrec)
	#else:
	#    query= db.GqlQuery("SELECT * from Blog"
	#    " ORDER BY created DESC")
	#    blogrec = query.fetch(limit=5)
	
	#QUERIED = "Queried %1f seconds ago" % age
	#age = time.time() - memcache.get(cacheAge)
	timecache = "Queried " + timecache.split('.')[0] +  " seconds ago"
	self.render("blog.html", blog=blogs, age = timecache)
	
    def get(self):
	self.write_blog()

    #def get(self):
	#numpost= 10
	#newno = int(self.request.get('numpost'))
	#if newno:
	#    query =db.GqlQuery("SELECT * FROM Blog"
	#		       "ORDER BY created DESC")
	#    blogrec = query.fetch(limit = newno)
	#    self.render("blog.html", blog = blogrec)
	#else:
	    
class blogjson(BaseHandler):
	def get(self):
		blogrec= db.GqlQuery("SELECT * from Blog"
		" ORDER BY created DESC")
		#json_query_data = json_parser(blogrec)
		results = []
		for post in blogrec:
			results.append({
							"subject": post.subject,
							"content": post.content,
							"created": post.created.strftime("%A %B %d %I:%M:%S %p %Y"),
							"Modified": post.last_modified.strftime("%A %B %d %I:%M:%S %p %Y"),
							"by": post.by,
							"Category": post.category,
							}
				)
		self.response.headers['Content-Type'] = "application/json"
		self.response.out.write(json.dumps(results, indent=4))

class NEWPOST(BaseHandler):
    def write_newpost(self, subject="", content="", error=""):
	self.render("newpost.html",subject=subject,content=content,  error=error)

    def get(self):
        self.write_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
	category = self.request.get("category")

        if subject and content:
            b=Blog(subject=subject, content=content, category = category)
            b.put()
	    id = b.key().id()
	    blog_cache(update=True)
            self.redirect("/blog/%s" %id)
        else:
            error="Both fields are required!!!"
            self.write_newpost(subject,content,error)
class removecache(Handler):
    def get(self):
	memcache.flush_all()
	self.redirect("/blog")
	
class Permalink(Handler):
    def get(self, blog_id):
        posts, timecache= post_cache(blog_id)
	#posts = Blog.get_by_id(int(blog_id))
	timecache = "Queried " + timecache.split('.')[0] +" seconds ago"
	if not posts:
	    self.render("404.html")
	self.render("post.html", blogs=posts, age=timecache)
	
class blogpermalink(BaseHandler):
	def get(self, blog_id):
		s = Blog.get_by_id(int(blog_id))
		json_data = [
					{
					"subject":s.subject,
					"content":s.content,
					"created": s.created.strftime("%A %B %d %I:%M:%S %p %Y"),
					"modified": s.last_modified.strftime("%A %B %d %I:%M:%S %p %Y"),
					"by": s.by,
					"Category":s.category,
					 }
					]
		self.response.headers['Content-Type'] = "application/json"
		self.response.out.write(json.dumps(json_data, indent=4))

app = webapp2.WSGIApplication([('/', IndexPage),('/formvalidation', Form),('/form/thanks',ThanksHandler),
                            ('/ROT13',ROT13),('/Signup',Signup),('/Signup/Welcome',Welcome),
('/ASCII',ASCII), ('/blog', BLOG),('/blog/newpost', NEWPOST),
		('/blog/([0-9]+)', Permalink),('/blog/signup', newuser),
		('/blog/login', Login), ('/blog/welcome',Welcome),
		('/blog/logout',logout),('/blog/.json',blogjson),
		('/blog/(\d+).json', blogpermalink),
		('/blog/flush', removecache),
		('/disp', disp_image),
		],debug=True)
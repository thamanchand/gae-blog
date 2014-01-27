from google.appengine.ext import db
class Art(db.Model):
    title= db.StringProperty(required = True)
    art= db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add=True)

class Blog(db.Model):
    subject = db.StringProperty(required= True)
    content= db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
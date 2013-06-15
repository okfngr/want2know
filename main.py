#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#
import webapp2
import os
import jinja2
import re
import hmac
import hashlib
import random
import urllib
from string import letters
from google.appengine.ext import db
from google.appengine.api import images
import time



template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True,extensions=['jinja2.ext.do'])
#password hash using salt
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in range(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

#cookie hashing and hash-validation functions
secret = 'weneverwalkalone'

def make_secure_cookie(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_cookie(val):
        return val

#RegEx
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

# Validation functions
def valid_username(username):
    return USERNAME_RE.match(username)
def valid_password(password):
    return PASSWORD_RE.match(password)
def valid_email(email):
        return not email or EMAIL_RE.match(email)

################ Databases ###################

class User(db.Model):
    username = db.StringProperty()
    password = db.StringProperty()
    email = db.StringProperty()
    registerday = db.DateProperty(auto_now_add = True)
    position = db.StringProperty()

class Applications(db.Model):
  title = db.StringProperty()
  description = db.TextProperty()
  img = db.BlobProperty()
  externallink = db.StringProperty()
  votes = db.IntegerProperty()
  tags = db.StringListProperty()
  author = db.StringProperty()
  date = db.DateProperty(auto_now_add = True)
  uservotes = db.StringListProperty()

class ContactForm(db.Model):
    name = db.StringProperty()
    email = db.EmailProperty()
    message = db.TextProperty()
    subject = db.StringProperty()

class Questions(db.Model):
    title = db.StringProperty()
    author = db.StringProperty()
    text = db.TextProperty()
    date = db.DateProperty(auto_now_add = True)
    votes = db.IntegerProperty()
    tags = db.StringListProperty()
    numanswers = db.IntegerProperty()
    uservotes = db.StringListProperty()
    
    
class Answers(db.Model):
    author = db.StringProperty()
    text = db.TextProperty()
    date = db.DateProperty(auto_now_add = True)
    identifier = db.StringProperty()
    stars = db.IntegerProperty()
    censusscore = db.IntegerProperty()
    censuslist = db.StringProperty(multiline=True)
    url = db.StringProperty()

class Newsletter(db.Model):
    email =  db.StringProperty()
    date = db.DateProperty(auto_now_add = True)

############### Helper Functions #############

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render_str_escaped(self, template, **params):
        t = jinja_env_escaped.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template,user=self.get_logged_in_user(), **kw))

    def render_content(self,template,**kw):
        questions = Questions.all()
        allusers = User.all()
        allanswers = Answers.all()
        tags = {}
        for question in questions:
            for tag in question.tags:
                if tag in tags.keys():
                    tags[tag] +=1
                else:
                    tags[tag] = 1

        self.write(self.render_str(template,user=self.get_logged_in_user(),tags=tags,allquestions=questions.count(),allusers=allusers.count(),allanswers=allanswers.count(), **kw))

    # method to see if a User is logged in or not
    def is_logged_in(self):
        user_id = None
        user = None
        user_id_str = self.request.cookies.get("user_id")
        if user_id_str:
            user_id = check_secure_val(user_id_str)
        return user_id

    # method that returns the actual logged in User
    def get_logged_in_user(self):
        user_id = self.is_logged_in()
        user = None
        if user_id:
            user = User.get_by_id(long(user_id))
        return user  


################# Main Page #################

class MainPageHandler(BaseHandler):
    def get(self):
        ## data for carousel on main page
        questions = Questions.all().order('-votes').fetch(5)

        self.render("index.html",questions=questions)



################ Log In #####################

class LoginHandler(BaseHandler):
    def get(self):
        self.render("login.html")

    def post(self):
            username = self.request.get("username")
            password = self.request.get("password")
                    

            u = User.gql("WHERE username = '%s'"%username).get()
            
            ## Check if user exist and if the password is correct    
            if u and valid_pw(username, password, u.password):
               uid= str(make_secure_cookie(str(u.key().id())))
               self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/" %uid)
               self.redirect('/')          

            else:
                msg = "Invalid login"
                self.render("login.html", error = msg)



################ Log Out ######################

class LogoutHandler(BaseHandler):
    def get(self):
        ## Delete cookies
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/")

################ Register ######################

class RegisterHandler(BaseHandler):
    

    def get(self):
        self.render("registration.html")

    def post(self):
        have_error  = False
        username    = self.request.get("username")
        email       = self.request.get("email")
        password    = self.request.get("password")
        confirm     = self.request.get("confirm_password")

        name_error = password_error = verify_error = email_error = ""
        username_error_div = password_error_div = confirm_error_div = email_error_div = ""

        if not valid_username(username):
            name_error = "That's not a valid username"
            username_error_div = "control-group error"
            have_error = True

        if not valid_password(password):
            password_error = "That's not a valid password"
            password_error_div = "control-group error"
            have_error = True 

        elif password != confirm:
            verify_error = "Your passwords didn't match"
            confirm_error_div = "control-group error"
            have_error = True

        if not valid_email(email):
            email_error = "That's not a valid email"
            email_error_div = "control-group error"
            have_error = True

        if have_error:
            self.render("registration.html"
                , username=username
                , username_error=name_error
                , password_error=password_error
                , verify_error=verify_error
                , email=email
                , email_error=email_error
                , username_error_div = username_error_div
                , password_error_div = password_error_div
                , confirm_error_div = confirm_error_div
                , email_error_div = email_error_div)
        else:      
           
           
           u = User.gql("WHERE username = '%s'"%username).get()
               
           if u:
                name_error = "That user already exists."
                username_error_div = "control-group error"
                self.render("registration.html", username=username, email=email, username_error = name_error, username_error_div = username_error_div)
           else:
            # make salted password hash
                h = make_pw_hash(username, password)
                u = User(username=username, password=h,email=email,position="member")

                u.put()
                uid= str(make_secure_cookie(str(u.key().id()))) #this is how we get the id from google data store(gapp engine)
        #The Set-Cookie header which is add_header method will set the cookie name user_id(value,hash(value)) to its value
                self.response.headers.add_header("Set-Cookie", "user_id=%s; Path=/" %uid)
                self.redirect("/")


############# Applications ######################

class ApplicationHandler(BaseHandler):
    def get(self):
        apps = Applications.all()
        recentapps = apps.order('-date').fetch(16)
        popularapps = apps.order('-votes').fetch(16)
        appsnumber = apps.count()
        tags = {}
        for app in apps:
            for tag in app.tags:
                if tag in tags.keys():
                    tags[tag] +=1
                else:
                    tags[tag] = 1 
        self.render("applications.html", tags=tags,recentapps = recentapps, popularapps = popularapps, appsnumber=appsnumber)

## class to handle the images of applications
class ApplicationImageHandler(BaseHandler):
    def get(self):
        sURL = self.request.url.split("/")
        app = Applications.get_by_id(long(sURL[-1]))
        self.response.headers['Content-Type'] = 'image/jpg'
        self.response.out.write(app.img)



############# Application Item ################

class ApplicationItemHandler(BaseHandler):
    def get(self, *a, **kw):
        sURL = self.request.url.split("/")
        app = Applications.get_by_id(long(sURL[-1]))
        self.render("application-item.html", app = app)

    def post(self, *a, **kw):
        sURL = self.request.url.split("/")
        app = Applications.get_by_id(long(sURL[-1]))
        voteup = self.request.get("voteup")
        votedown = self.request.get("votedown")
        if voteup:

            if not self.get_logged_in_user():
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Δε μπορείς να ψηφίσεις χωρίς να συνδεθείς.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render("application-item.html", app = app,error=error)
            
            elif str(self.get_logged_in_user().key().id()) in app.uservotes:
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Έχεις ήδη ψηφίσει γι' αυτήν την εφαρμογή.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render("application-item.html", app = app,error=error)

            else:
                app.votes += 1
                app.uservotes.append(str(self.get_logged_in_user().key().id()))
                app.put()
                self.render("application-item.html", app = app)

        if votedown:
            if not self.get_logged_in_user():
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Δε μπορείς να ψηφίσεις χωρίς να συνδεθείς.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render("application-item.html", app = app,error=error)
            

            elif str(self.get_logged_in_user().key().id()) in app.uservotes:
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Έχεις ήδη ψηφίσει γι' αυτήν την εφαρμογή.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render("application-item.html", app = app,error=error)
            else:
                app.uservotes.append(str(self.get_logged_in_user().key().id()))
                app.votes -= 1
                app.put()
                self.render("application-item.html", app = app)


########### Contact Form ###############

class ContactFormHandler(BaseHandler):
    def get(self):
        self.render("contact.html")

    def post(self):
        name = self.request.get("name")
        email = self.request.get("email")
        message = self.request.get("message")
        subject = self.request.get("subject")
        contact = ContactForm(name = name, email=email, subject = subject, message = message)
        contact.put()
        text = '''<div class="alert alert-info">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            Ευχαριστούμε που επικοινωνήσατε μαζί μας. Σύντομα κάποιος εκπρόσωπος του want2know θα σας απαντήσει
                            </div> '''
        text = unicode(text,"utf-8")
        self.render("contact.html",text=text)

############## Questions ###################

class QuestionsHandler(BaseHandler):
    def get(self):
        allusers = User.all()
        allanswers = Answers.all()
        questions = Questions.all()
        newquestions = Questions.all().order('-date').fetch(15)
        popquestions = Questions.all().order('-votes').fetch(15)
        noanswerquestions = Questions.gql("WHERE numanswers = 0").fetch(15)
        self.render_content("questions.html", newquestions = newquestions,popquestions=popquestions,noanswerquestions = noanswerquestions,tab1_act="active")


## All questions handler
class AllQuestionsHandler(BaseHandler):
    def get(self):
        questions = Questions.all()
        self.render_content("allquestions.html", questions=questions)


############## Ask a question ###############

class AskHandler(BaseHandler):
    def get(self):
        self.render("makeaquestion.html")

    def post(self):
        askbutton = self.request.get("askbutton")
        title = self.request.get("title")
        message = self.request.get("message")
        tags = self.request.get("HiddenTags")

        if self.is_logged_in():
        
            if askbutton:
                title = self.request.get("askquestion")
                self.render("makeaquestion.html",title=title)   
        
            if message:
                u = Questions.gql("WHERE title = '%s'"%title).get()
                if u:
                    error = '''<div class="alert alert-info">
                     <button type="button" class="close" data-dismiss="alert">&times; </button>
                     <strong>Προσοχή! </strong> Υπάρχει ήδη ερώτηση με τον ίδιο τίτλο.
                    </div>'''
                    error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                    self.render("makeaquestion.html",error=error)
                else:
                    question = Questions(title=title,author=self.get_logged_in_user().username,text=message,votes=0,numanswers=0,tags=tags.split(","),uservotesup=[],uservotesdown=[])
                    question.put()
                    self.redirect("/questions/"+str(question.put().id()))
        else:
            self.render("makeaquestion.html")

        


########### Question Page #############

class QuestionPageHandler(BaseHandler):
    def get(self, *a, **kw):
        
        sURL = self.request.url.split("/")
        question = Questions.get_by_id(long(sURL[-1]))
        answers = Answers.gql("WHERE identifier='%s'"%long(sURL[-1])).run()
        numanswers = Answers.gql("WHERE identifier='%s'"%long(sURL[-1])).count()
        self.render_content("questionpage.html",question=question,answers=answers,numanswers=numanswers)

    def post(self, *a, **kw):
        sURL = self.request.url.split("/")
        question = Questions.get_by_id(long(sURL[-1]))
        answers = Answers.gql("WHERE identifier='%s'"%long(sURL[-1])).run()
        answer = self.request.get("answerbutton")
        voteup = self.request.get("voteup")
        votedown = self.request.get("votedown")
        deletequestion = self.request.get("deletequestion")


        if deletequestion:
            question = Questions.get_by_id(long(sURL[-1]))
            answers = Answers.gql("WHERE identifier='%s'"%long(sURL[-1])).run()
            question.delete()
            for answer in answers:
                answer.delete()
                time.sleep(0.1)
            self.redirect("/questions")

        if answer:

            answer = self.request.get("answer")
            censuslist = self.request.get_all("censuslist")
            url = self.request.get("url")
            strings = ""
            censusscore = 0

            ## Python cannot recognise Greek in list of strings when you make a request and we use the following system
            if str(0) in censuslist:
                strings = strings + "<br>" + (unicode("Τα δεδομένα υπάρχουν","utf-8"))
            if str(1) in censuslist:
                strings = strings + "<br>" + (unicode("Είναι σε ψηφιακή μορφή","utf-8"))
                censusscore += 1
            else:
                strings= strings + "<br>" + (unicode("Δεν είναι σε ψηφιακή μορφή","utf-8"))
            if str(2) in censuslist:
                strings = strings + "<br>" + (unicode("Είναι αναγνώσιμα από υπολογιστή (π.χ. excel και όχι pdf)","utf-8"))
                censusscore += 1
            else:
                strings = strings + "<br>" + (unicode("Δεν είναι αναγνώσιμα από υπολογιστή (π.χ. excel και όχι pdf)","utf-8"))
            if str(3) in censuslist:
                strings = strings + "<br>" + (unicode("Είναι εύκολα διαθέσιμα","utf-8"))
                censusscore += 1
            else:
                strings = strings + "<br>" + (unicode("Δεν είναι εύκολα διαθέσιμα","utf-8"))
            if str(4) in censuslist:
                strings = strings + "<br>" + (unicode("Είναι δωρεάν","utf-8"))
                censusscore += 1
            else:
                strings = strings + "<br>" + (unicode("Δεν είναι δωρεάν","utf-8"))
            if str(5) in censuslist:
                strings = strings + "<br>" + (unicode("Έχουν ανοιχτή άδεια; (ως προς το opendefinition.org)","utf-8"))
                censusscore += 1
            else:
                strings = strings + "<br>" + (unicode("Δεν έχουν ανοιχτή άδεια; (ως προς το opendefinition.org)","utf-8"))
            if str(6) in censuslist:
                strings = strings + "<br>" + (unicode("Είναι ανανεωμένα","utf-8"))
                censusscore += 1
            else:
                strings = strings + "<br>" + (unicode("Δεν είναι ανανεωμένα","utf-8"))
            if str(0) not in censuslist:
                strings = unicode("Τα δεδομένα δεν υπάρχουν","utf-8")
                censusscore = 0

            answer = Answers(censuslist = strings, censusscore = censusscore, url =url, author=self.get_logged_in_user().username,text=answer,identifier=sURL[-1])
            answer.put()
            time.sleep(0.1)
            question = Questions.get_by_id(long(sURL[-1]))
            question.numanswers += 1
            question.put()
            time.sleep(0.1)
            numanswers = Answers.gql("WHERE identifier='%s'"%long(sURL[-1])).count()
            self.render_content("questionpage.html",question=question,answers=answers,numanswers=numanswers)

        if voteup:
            author = User.gql("WHERE username = '%s'"%question.author).get()

            if not self.get_logged_in_user():
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Δε μπορείς να ψηφίσεις ερώτηση χωρίς να συνδεθείς.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render_content("questionpage.html",question=question,answers=answers,error=error)
            elif author.username == self.get_logged_in_user().username:
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Δε μπορείς να ψηφίσεις ερώτηση που έχεις κάνει ο ίδιος.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render_content("questionpage.html",question=question,answers=answers,error=error)
            
            elif str(self.get_logged_in_user().key().id()) in question.uservotes:
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Έχεις ήδη ψηφίσει γι' αυτήν την ερώτηση.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render_content("questionpage.html",question=question,answers=answers,error=error)

            else:
                question.votes += 1
                question.uservotes.append(str(self.get_logged_in_user().key().id()))
                question.put()
                self.render_content("questionpage.html",question=question,answers=answers)

        if votedown:
            author = User.gql("WHERE username = '%s'"%question.author).get()
            if not self.get_logged_in_user():
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Δε μπορείς να ψηφίσεις ερώτηση χωρίς να συνδεθείς.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render_content("questionpage.html",question=question,answers=answers,error=error)
            elif author.username == self.get_logged_in_user().username:
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Δε μπορείς να ψηφίσεις ερώτηση που έχεις κάνει ο ίδιος.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render_content("questionpage.html",question=question,answers=answers,error=error)

            elif str(self.get_logged_in_user().key().id()) in question.uservotes:
                error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            <strong>Προσοχή! </strong> Έχεις ήδη ψηφίσει γι' αυτήν την ερώτηση.
                            </div> '''
                error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
                self.render_content("questionpage.html",question=question,answers=answers,error=error)   
            else:
                question.uservotes.append(str(self.get_logged_in_user().key().id()))
                question.votes -= 1
                question.put()
                self.render_content("questionpage.html",question=question,answers=answers)


###################### About Us #################

class AboutUsHandler(BaseHandler):
    def get(self):
        self.render("aboutus.html")


################ Categories ####################

class CategoryHandler(BaseHandler):
    def get(self, *a, **kw): 
        sURL = self.request.url.split("/")
        category = sURL[-1]
        category = urllib.unquote_plus(category)
        category = unicode(category,"utf-8")
        results = Questions.gql("WHERE tags in :1", [category]).run()
        self.render_content("categories.html",questions=results)

############### Search ########################

class SearchQuestionHandler(BaseHandler):
    def post(self):
        keyword = self.request.get("keyword")
        questions = Questions.all()
        results = []
        for question in questions:
            if keyword in question.title:
                results.append(question)
        if results == []:
            error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            Δε βρέθηκαν αποτελέσματα με το keyword που ψάχνετε
                            </div> '''
            error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
            self.render_content("allquestions.html",error=error)
        else:
            self.render_content("allquestions.html",questions = results)

#################### Search App ########################

class SearchAppHandler(BaseHandler):
    def post(self):
        keyword = self.request.get("keyword")
        apps = Applications.all()
        results = []
        for app in apps:
            if keyword in app.title:
                results.append(question)
        if results == []:
            error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            Δε βρέθηκαν αποτελέσματα με το keyword που ψάχνετε
                            </div> '''
            error = unicode(error,"utf-8") # If you don't use greek characters, remove this line
            self.render("allapplications.html",applications=apps,error=error)
        else:
            self.render("allapplications.html",results = results)


##################### Statistics ########################

class StatisticsHandler(BaseHandler):
    def get(self):
        questions = Questions.all()
        tags = {}
        for question in questions:
            for tag in question.tags:
                if tag in tags.keys():
                    tags[tag] +=1
                else:
                    tags[tag] = 1
        categories = []
        for tag in tags:
                tag2 = tag.encode("utf-8")
                tag3 = unicode(tag2,"utf-8")
                categories.append([tag3,int(tags[tag])])
    

        answers = Answers.all()
        stars = {}
        for i in range(1,6):
            stars[i] = 0
        for answer in answers:
            try:
                stars[answer.stars] +=1
            except:
                pass
        answerstardata = []
        for star in stars:
            answerstardata.append(int(stars[star]))

        score = {}
        for i in range(0,7):
            score[i] = 0
        for answer in answers:
            try:
                score[answer.censusscore] += 1
            except:
                pass
        censusscoredata = []
        for cs in score:
            censusscoredata.append(int(score[cs]))

        self.render("statistics.html",censusscore = censusscoredata,categories = categories, answerstardata = answerstardata)

############## Admin Panel ######################

class AdminHandler(BaseHandler):
    def get(self):
        contacts = ContactForm.all()
        self.render("admin.html",contacts=contacts)
        

    def post(self):
        app = Applications()
        app.title = self.request.get('title')
        app.author = self.request.get('author')
        app.description = self.request.get('description')
        image = images.resize(self.request.get('image'), 400, 400)
        app.img = db.Blob(image)
        app.externallink = self.request.get("externallink")
        app.tags = self.request.get("HiddenTags").split(",")
        app.votes = 0
        app.put()
        
        self.render("admin.html")


################ Open data ###############

class OpenDataHandler(BaseHandler):
    def get(self):
        self.render("opendata.html")

############### Privacy ###################

class PrivacyHandler(BaseHandler):
    def get(self):
        self.render("privacy.html")

############### Terms of Use ###################

class TermofuseHandler(BaseHandler):
    def get(self):
        self.render("termofuse.html")

############## Newsletter #################

class NewsletterHandler(BaseHandler):
    def get(self):
        self.render("newsletter.html")

    def post(self):
        email = self.request.get("email")

        u = Newsletter.gql("WHERE email = '%s'"%email).get()
               
        if u:
            email_error = '''<div class="alert alert-error">
                            <button type="button" class="close" data-dismiss="alert">&times; </button>
                            Το e-mail υπάρχει ήδη στη λίστα ενημέρωσης.
                            </div> '''
            email_error = unicode(email_error,"utf-8") # If you don't use greek characters, remove this line

            self.render("newsletter.html", email_error = email_error)
        else:
            new = Newsletter()
            new.email = email
            new.put()
            self.render("newsletter.html")

############ All applications ################

class AllApplicationsHandler(BaseHandler):
    def get(self):
        apps = Applications.all()
        tags = {}
        for app in apps:
            for tag in app.tags:
                if tag in tags.keys():
                    tags[tag] +=1
                else:
                    tags[tag] = 1 
        self.render("allapplications.html",tags=tags, apps=apps)

############### FAQ ######################

class FAQHandler(BaseHandler):
    def get(self):
        self.render("faq.html")


############## Handlers #############################    

PAGE_RE = r'((?:[a-zA-Z0-9_-]+/?)*)?'

app = webapp2.WSGIApplication([('/', MainPageHandler)
                            ,('/registration', RegisterHandler)
                            ,('/login', LoginHandler)
                            ,('/logout', LogoutHandler)
                            ,('/applications', ApplicationHandler)
                            ,('/applications/'+PAGE_RE, ApplicationItemHandler)
                            ,("/admin",AdminHandler)
                            ,('/images/.*', ApplicationImageHandler)
                            ,("/contact", ContactFormHandler)
                            ,("/questions", QuestionsHandler)
                            ,("/askaquestion", AskHandler)
                            ,('/questions/'+PAGE_RE, QuestionPageHandler)
                            ,('/allquestions', AllQuestionsHandler)
                            ,('/opendata', OpenDataHandler)
                            ,('/aboutus', AboutUsHandler)
                            ,('/category/.*', CategoryHandler)
                            ,('/searchquestion', SearchQuestionHandler)
                            ,('/searchapp', SearchAppHandler)
                            ,('/statistics', StatisticsHandler)
                            ,('/privacy', PrivacyHandler)
                            ,('/newsletter',NewsletterHandler)
                            ,('/termsofuse',TermofuseHandler)
                            ,('/allapplications',AllApplicationsHandler)
                            ,('/faq', FAQHandler)
                            ],debug=True)

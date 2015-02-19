import os, sys
sys.path.append('/srv/www/stampurapp')
os.environ['PYTHON_EGG_CACHE'] = '/srv/www/.python-egg'

import resources
#import feeder
import mongoengine 

import json
import hashlib
import uuid
import urlparse
import datetime
import math
import base64
import hmac
import httplib

import pylibmc
import bleach
import webob
import webob.exc
import bson

import routes
import routes.middleware
from mongoengine import *

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

mc = pylibmc.Client(['127.0.0.1:11211'], binary=True, behaviors={"tcp_nodelay": True})

routes_map = routes.Mapper()

routes_map.resource("stamp", "stamps", path_prefix="/json")
routes_map.resource("user", "users", path_prefix="/json")
routes_map.resource("message", "messages", path_prefix="/json")
routes_map.resource("collection", "collections", path_prefix="/json")
routes_map.resource("comment", "comments", path_prefix="/json/messages/{message_id}")

routes_map.connect(None, "/mediaload/{action}", controller="media")
routes_map.connect(None, "/auth/{action}", controller="auth")
routes_map.connect(None, "/{resource}/{id}/", controller="root")
routes_map.connect(None, "/{resource}/{id}", controller="root")
routes_map.connect(None, "/{resource}", controller="root")
routes_map.connect(None, "/", controller="root")


def to_message_object(message, user=None):
    return {
        'id':str(message.id),
        'body':message.body,
        'subject':message.subject,
        'timestamp':message.date_created.isoformat(),
        'date':message.date_created.strftime("%b. %d").lower(),
        'ups':message.ups,
        'title':message.subject,
        'downs':message.downs,
        'photos':message.photos,
        'score':message.ups - message.downs,
        'num_replies':message.num_replies,
        'uped':message in user.uped_messages if user else False,
        'downed':message in user.downed_messages if user else False,
        'stamps':[to_stamp_object(tag, user) for tag in message.tags],
        'is_author':user == message.author if user else False
        }
        
def to_message_object_wstamps(message, user=None):
    return {
        'id':str(message.id),
        'body':message.body,
        'subject':message.subject,
        'timestamp':message.date_created.isoformat(),
        'date':message.date_created.strftime("%b. %d").lower(),
        'ups':message.ups,
        'title':message.subject,
        'downs':message.downs,
        'uped':message in user.uped_messages if user else False,
        'downed':message in user.downed_messages if user else False,
        'comments':[to_comment_object(comment_child) for comment_child in message.comments],
        'photos':message.photos,
        'score':message.ups - message.downs,
        'num_replies':message.num_replies,
        'stamps':[to_stamp_object(tag, user) for tag in message.tags],
        'is_author':user == message.author if user else False
        }

def to_stamp_object(stamp, user=None):
    if stamp['tag_type'] == 'user':
        if not 'stamp_image' in stamp:
            stamp['stamp_image'] = 'personal_stamp_bkground'
    else:
        stamp['tag_type'] = 'public'
        
    if not 'stamp_image' in stamp:
        stamp['stamp_image'] = 'general_stamp_bkground'
        
    if stamp['stamp_image'] == 'staff_stamp_bkground':
        stamp['tag_type'] = 'staff'
    if stamp['stamp_image'] == 'stampurstamp_sel':
        stamp['tag_type'] = 'stampurstamp'
    return {
        'id':str(stamp['id']),
        'label':stamp['label'],
        'num_messages': len(resources.Message.objects(tags=stamp)),
        "photo":stamp['photos'],
        'type':stamp['tag_type'],
        'location':stamp['location'] if 'location' in stamp else None,
        'category':stamp['category'],
        'description':stamp['toolTip'],
        'stamp_image':stamp['stamp_image'] if 'stamp_image' in stamp else None,
        'in_stampbook':stamp in user.tag_bucket if user else False,
        'num_users':stamp['numUsers']
        }
        
def to_comment_object(comment, user=None):
    return {
        'id':str(comment.id), 
        'comments':[to_comment_object(comment_child, user) for comment_child in comment.comments], 
        'timestamp':comment.date_created.isoformat(),
        'date':comment.date_created.strftime("%b. %d").lower(),
        'body':comment.body.replace('\n','<br>'),
        'score':comment.ups-comment.downs,
        'author_id':None if comment.anonymous else str(comment.author.personal_tag.id),
        'author':None if comment.anonymous else comment.author.personal_tag.label,
        'is_author':False if not user else comment.author == user,
        'private_with': comment.private_with if 'private_with' in comment else None
        }
def to_comment_object_one(comment):
    return {
        'id':str(comment['id']), 
        'timestamp':comment['date_created'].isoformat(),
        'date':comment['date_created'].strftime("%b. %d").lower(),
        'body':comment['body'].replace('\n','<br>'),
        'score':comment['ups']-comment['downs'],
        'author_id':None if comment['anonymous'] else str(comment['author']['personal_tag']['_id']),
        'author':None if comment['anonymous'] else comment['author']['personal_tag']['label'],
        'private_with': comment['private_with'] if 'private_with' in comment else None
        }
def get_ranking(message):
    epoch = datetime.datetime(1970, 1, 1)
    td = message.date_created - epoch
    seconds = td.days * 86400 + td.seconds + (float(td.microseconds) / 1000000) - 1134028003
    score = message.ups - message.downs
    score = 4*score + (4 * message.num_replies)
    order = 1.8 * math.log(max(abs(score), 1), 10)
    sign = 1 if score > 0 else -1 if score < 0 else 0
    return round(order + sign * seconds / 45000, 7)

def base64_url_decode(inp):
    padding_factor = (4 - len(inp) % 4) % 4
    inp += "="*padding_factor 
    return base64.b64decode(unicode(inp).translate(dict(zip(map(ord, u'-_'), u'+/'))))

def parse_signed_request(signed_request, secret):

    l = signed_request.split('.', 2)
    encoded_sig = l[0]
    payload = l[1]

    sig = base64_url_decode(encoded_sig)
    data = json.loads(base64_url_decode(payload))

    if data.get('algorithm').upper() != 'HMAC-SHA256':
        print 'Unknown algorithm'
        return None
    else:
        expected_sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).digest()

    if sig != expected_sig:
        return None
    else:
        print 'valid signed request received..'
        return data

class root:
    def __init__(self, request):
        self.request = request
        self.res = webob.Response()
        self.qs_dict = urlparse.parse_qs(self.request.query_string)
        self.current_connection_instance = resources.connection._get_connection(reconnect = False)
    def __call__(self):
        loggedin = False
        location = None
        page = None
        resource = None
        bad_login = None
        id = None
        user = None
        print self.request.url
        if 'auth_tkt' in self.request.cookies:
            loggedin = True
            userid = mc.get(str(self.request.cookies['auth_tkt']))
            user = resources.User.objects.get(id=userid)
            resource = 'stampurstamp'
        else:
            resource = 'stampurstamp'
        if 'resource' in self.request.urlvars:
            resource = self.request.urlvars['resource']
        if 'page' in self.qs_dict:
            page = self.qs_dict['page'][0]
        else:
            page = 1
        if 'id' in self.request.urlvars:
            id = self.request.urlvars['id']
        if 'bad_login' in self.qs_dict:
            bad_login = True
        action = 'load'
        if resource == 's':
            action = 'view_stamp'
            resource = id
        elif resource == 'mystampbook':
            action = 'loadTagsBin'
        elif resource == 'messages':
            action = 'showFullMessage'
            resource = id
        collections = []
        my_stamps = []
        if user:
            
            for stamp in sorted(user.tag_bucket, key=lambda stamp: stamp.label):
                my_stamps.append(to_stamp_object(stamp,user))
            if 'collections' in self.current_connection_instance.soapboxdb.user.find({ '_id':user.id})[0]:
                print self.current_connection_instance.soapboxdb.user.find({ '_id':user.id})[0]['collections']
                for collection in user['collections']:
                    collection = resources.StampCollection.objects.get(id=collection.id)
                    collections.append({'name':collection.name,'id':str(collection.id)})
        self.res.body = json.dumps({'collections':collections,'my_stamps':my_stamps, 'loggedin':loggedin,'action':action,'resource':resource,'page':page,'id':id,'bad_login':bad_login})
        return self.res

class media:
    def __init__(self, request):
        self.request = request
        self.res = webob.Response()
        self.qs_dict = urlparse.parse_qs(self.request.query_string)
    def __call__(self):
        if self.request.urlvars['action'] == 'image':
            self.res.body = self.upload_image()
        return self.res
    def upload_image(self):
        filename = str(uuid.uuid4()) + os.path.splitext(self.request.headers['X-File-Name'])[1]
        f = open('/srv/stampur_media/image/' + filename, 'a')
        f.write(self.request.body)
        f.close()
        os.system("mogrify -resize 1024x1024 /srv/stampur_media/image/" + filename)
        f = open('/srv/stampur_media/image/thumb/' + filename, 'a')
        f.write(self.request.body)
        f.close()
        os.system("mogrify -resize 256x256 /srv/stampur_media/image/thumb/" + filename)
        return filename
    

class InvalidUser(Exception):
    pass


class auth:
    def __init__(self, request):
        self.request = request
        self.res = webob.exc.HTTPFound(location="/")
        self.qs_dict = urlparse.parse_qs(self.request.query_string)
        self.current_connection_instance = resources.connection._get_connection(reconnect = False)
        
    def __call__(self):
        if self.request.urlvars['action'] == 'login_post':
            self.login_post()
        elif self.request.urlvars['action'] == 'logout':
            self.logout()
        elif self.request.urlvars['action'] == 'login':
            self.res.body = self.login()
        elif self.request.urlvars['action'] == 'forgot_pass':
            self.forgot_pass()
        elif self.request.urlvars['action'] == 'reset':
            self.reset()
        elif self.request.urlvars['action'] == 'register_post':
            self.register_post()
        elif self.request.urlvars['action'] == 'do_register':
            self.do_register()
        elif self.request.urlvars['action'] == 'confirm':
            self.confirm()
        return self.res
        
    def login_post(self):
        try:
            user = self.authenticate_user(self.request.params['email'], self.request.params['password'])
        except InvalidUser, e:
            self.res = webob.exc.HTTPFound(location="/stampurstamp?page=1&bad_login=true")
            return '/bad_login'
        auth_tkt = str(uuid.uuid4())
        mc.set(auth_tkt, str(user.id))
        self.res.set_cookie('auth_tkt', auth_tkt)
        return 'now logged in!'
        
    def do_register(self):
        self.res = webob.Response()
        data = json.loads(self.request.body)
        user = resources.UnconfirmedUser()
        self.res.body = json.dumps({});
        email_in_use = True
        error_response = {'email_error': '','username_error': ''}
        print data
        try:
            result = resources.User.objects.get(email=data['email'])
        except resources.User.DoesNotExist, e:
            email_in_use = False
            try:
                result = resources.User.objects.get(email=data['email'])
                email_in_use = True
            except resources.User.DoesNotExist, e:
                email_in_use = False
        if email_in_use:
            error_response['email_error'] = 'Email already in use :/'
        else:
            user.email_uc = data['email']
        user.location = [34.420830000000002, -119.69819000000001]
        username_in_use = True
        try:
            result = resources.User.objects.get(username=data['username'])
        except resources.User.DoesNotExist, e:
            username_in_use = False
            try:
                result = resources.User.objects.get(username=data['username'])
                username_in_use = True
            except resources.User.DoesNotExist, e:
                username_in_use = False
        if username_in_use:
            error_response['username_error'] = 'Username is already in use :/'
        else:
            user.username = data['username']
        if username_in_use or email_in_use:
            self.res.body = json.dumps(error_response)
            self.res.status = 403
            return
        user.email = str(uuid.uuid4())
        user.password, user.salt = gen_hash_password(data['password'])
        user.save() 
        From = 'stampur_team@stampur.com'
        To = user.email_uc
        SUBJECT = 'Welcome to Stampur!'
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Welcome to Stampur!'
        msg['From'] = From
        msg['To'] = To
        text = str(user.id)
        html = """\
<html>
<body lang=3D"en" style=3D"background-color:#fff; color: #222">
<div style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:13px; margin: 14px; position:relative">
<h2 style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif;margin:0 0 16px; font-size:18px; font-weight:normal">
Welcome to Stampur!</h2>

<p>To confirm your email address, please click <a href="http://stampur.com/auth/confirm?id=%s">here</a>.<br /></p>
</body>
</html>""" % (str(user.id))    
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        s.login('kyle@stampur.com','H214tZ18J*9m')
        try:
            s.sendmail(From, To, msg.as_string())
        except smtplib.SMTPRecipientsRefused, e:
            error_response['email_error'] = 'Please enter a valid email address.'
            self.res.body = json.dumps(error_response)
            self.res.status = 403
            return
        s.quit()
        self.res.body = 'Please check your email to complete registration.'
        return

    
    def register_post(self):
        self.res = webob.Response()
        out = parse_signed_request(self.request.body[15:],'39c556e2a1a8d694d29e0bd00db0d4eb')
        user = resources.UnconfirmedUser()
        email_in_use = True
        try:
            result = resources.User.objects.get(username=out['registration']['email'])
        except resources.User.DoesNotExist, e:
            email_in_use = False
            try:
                result = resources.UnconfirmedUser.objects.get(username=out['registration']['email'])
                email_in_use = True
            except resources.UnconfirmedUser.DoesNotExist, e:
                email_in_use = False
        if email_in_use:
            self.res.body = 'email already in use it seems :/'
            return
        else:
            user.email = out['registration']['email']
        user.location = [34.420830000000002, -119.69819000000001]
        username_in_use = True
        try:
            result = resources.User.objects.get(username=out['registration']['username'])
        except resources.User.DoesNotExist, e:
            username_in_use = False
            try:
                result = resources.UnconfirmedUser.objects.get(username=out['registration']['username'])
                username_in_use = True
            except resources.UnconfirmedUser.DoesNotExist, e:
                username_in_use = False
        if username_in_use:
             self.res.body = 'username already in use it seems :/'
             return
        else:
            user.username = out['registration']['username']
        user.dob = datetime.datetime.strptime(out['registration']['birthday'], '%m/%d/%Y')
        if out['registration']['gender'] not in ['male','female']:
            self.res.body = 'gender invalid :/'
            return
        user.sex = out['registration']['gender']
        user.password, user.salt = gen_hash_password(out['registration']['password'])
        user.save()
        From = 'stampur_team@stampur.com'
        To = user.email
        SUBJECT = 'Welcome to Stampur!'
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'Welcome to Stampur!'
        msg['From'] = From
        msg['To'] = To
        text = str(user.id)
        html = """\
<html>
<body lang=3D"en" style=3D"background-color:#fff; color: #222">
<div style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:13px; margin: 14px; position:relative">
<h2 style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif;margin:0 0 16px; font-size:18px; font-weight:normal">
Welcome to Stampur!</h2>

<p>To confirm your email address, please click <a href="http://stampur.com/auth/confirm?id=%s">here</a>.<br /></p>
</body>
</html>""" % (str(user.id))    
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)
        s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        s.login('kyle@stampur.com','H214tZ18J*9m')
        s.sendmail(From, To, msg.as_string())
        s.quit()
        self.res.body = 'Please check your email to complete registration!'
        return
    
    def confirm(self):
        self.res = webob.Response()
        id = reset_tkt = self.qs_dict['id'][0]
        if not id:
            return Response(body="confirmation not found!")
        try:
            unconfirmed = resources.UnconfirmedUser.objects.get(id=id)
        except resources.User.DoesNotExist, e:
            self.res.body = 'bad id'
            return
        except ValidationError, e:
            self.res.body = 'bad id'
            return
        personal_tag = resources.Tag()
        personal_tag.label = unconfirmed.username
        personal_tag.tag_type = 'user'
        personal_tag.tag_permission = 2
        personal_tag.save()
        user = resources.User()
        user.email = unconfirmed.email_uc
        user.password = unconfirmed.password
        user.location = [34.420830000000002, -119.69819000000001]
        user.sex = unconfirmed.sex
        user.dob = unconfirmed.dob
        user.first_name = unconfirmed.first_name
        user.last_name = unconfirmed.last_name
        user.username = unconfirmed.username
        user.salt = unconfirmed.salt
        user.date_created = unconfirmed.date_created
        user.location = unconfirmed.location
        user.personal_tag = personal_tag
        user.save()
        unconfirmed.delete()
        self.res = webob.exc.HTTPFound(location="/")
        auth_tkt = str(uuid.uuid4())
        mc.set(auth_tkt, str(user.id))
        self.res.set_cookie('auth_tkt', auth_tkt)
        print '\nCONFIRMED -- ' + unconfirmed.email + ', ' + unconfirmed.username 
        return
    
    def forgot_pass(self):
        self.res = webob.Response()
        email = self.request.body
        print email
        if len(email) < 5:
            self.res.body = 'Invalid email address!'
        else:
            try:  
                user = resources.User.objects.get(email__iexact=email)
                reset_tkt = str(uuid.uuid4())
                From = 'stampur_team@stampur.com'
                To = user.email
                SUBJECT = 'We forget our passwords too :/'
                msg = MIMEMultipart('alternative')
                msg['Subject'] = 'We forget our passwords too :/'
                msg['From'] = From
                msg['To'] = To
                text = str(user.id)
                html = """\
        <html>
        <body lang=3D"en" style=3D"background-color:#fff; color: #222">
        <div style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:13px; margin: 14px; position:relative">
        <h2 style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif;margin:0 0 16px; font-size:18px; font-weight:normal">
        If you didn't want to reset your password, please ignore this email.</h2>

        <p>To reset your password, please click <a href="http://stampur.com/auth/reset?reset_tkt=%s">here</a>.<br /></p>
        </body>
        </html>""" % (reset_tkt)
                part1 = MIMEText(text, 'plain')
                part2 = MIMEText(html, 'html')
                msg.attach(part1)
                msg.attach(part2)
                s = smtplib.SMTP_SSL('smtp.gmail.com', 465)
                s.login('kyle@stampur.com','H214tZ18J*9m')
                s.sendmail(From, To, msg.as_string())
                s.quit()
                mc.set(reset_tkt, str(user.id))
                self.res.body = 'Please check your email for a reset link.'
            except resources.User.DoesNotExist, e:
                self.res.body = 'Hm, we couldn\'t find your email, please register instead.'
            
    
    def reset(self):
        self.res = webob.Response()
        reset_tkt = self.qs_dict['reset_tkt'][0] if 'reset_tkt' in self.qs_dict else None
        try:
            userid = mc.get(str(reset_tkt))
            try:
                user = resources.User.objects.get(id=userid)
                new_password = str(uuid.uuid4())[0:6]
                From = 'stampur_team@stampur.com'
                To = user.email
                SUBJECT = 'Password reset!'
                msg = MIMEMultipart('alternative')
                msg['Subject'] = 'Password reset!'
                msg['From'] = From
                msg['To'] = To
                text = str(user.id)
                html = """\
        <html>
        <body lang=3D"en" style=3D"background-color:#fff; color: #222">
        <div style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:13px; margin: 14px; position:relative">
        <h2 style=3D"font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif;margin:0 0 16px; font-size:18px; font-weight:normal">
        Please change your password as soon as you can.</h2>

        <p>Your new password is: %s<br /></p>
        </body>
        </html>""" % (new_password)
                part1 = MIMEText(text, 'plain')
                part2 = MIMEText(html, 'html')
                msg.attach(part1)
                msg.attach(part2)
                mc.delete(reset_tkt)
                user.password, user.salt = self.gen_hash_password(new_password)
                self.current_connection_instance.soapboxdb.user.update({ '_id':user.id},{ '$set' : { 'password' : user.password, 'salt': user.salt } })
                s = smtplib.SMTP_SSL('smtp.gm1ail.com', 465)
                s.login('kyle@stampur.com','H214tZ18J*9m')
                s.sendmail(From, To, msg.as_string())
                s.quit()
                
                self.res.body = 'ooookay, I emailed you a new password.'
            except mongoengine.base.ValidationError, e:
                print e
                self.res.body = 'bad reset_tkt'
        except InvalidUser, e:
            self.res.body = 'bad reset_tkt'
        
    
    def login(self):
        self.res = webob.Response()
        try:
            if 'facebook_auth_token' in self.qs_dict:
                conn = httplib.HTTPSConnection("graph.facebook.com")
                conn.request("GET", "/me?access_token=" + self.qs_dict['facebook_auth_token'][0])
                r1 = conn.getresponse()
                fbres = json.loads(r1.read())
                try:
                    email = fbres['email'].replace('%40','@')
                    print email
                    user = resources.User.objects.get(email__iexact=email)
                    auth_tkt = str(uuid.uuid4())
                    mc.set(auth_tkt, str(user.id))
                    return str(auth_tkt)
                except resources.User.DoesNotExist, e:
                    raise InvalidUser('bad email')
            username = self.qs_dict['email'][0] if 'email' in self.qs_dict else ''
            password = self.qs_dict['password'][0] if 'password' in self.qs_dict else ''
            username = username.replace('%40','@')
            print username
            print password
            user = self.authenticate_user(username, password)
        except InvalidUser, e:
            self.res.status = 403
            return '/bad_login'
        auth_tkt = str(uuid.uuid4())
        mc.set(auth_tkt, str(user.id))
        return str(auth_tkt)
        
    def logout(self):
        if 'auth_tkt' in self.request.cookies:
            mc.delete(self.request.cookies['auth_tkt'])
            self.res.delete_cookie('auth_tkt')
            return 'now logged out!'
        return 'hm no auth cookie :/'
        
    def hash_password(self, password, salt):
        m = hashlib.sha256()
        m.update(password)
        m.update(salt)
        return m.hexdigest()

    def gen_hash_password(self, password):
        import random
        letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
        p = ''
        random.seed()
        for x in range(32):
            p += letters[random.randint(0, len(letters)-1)]
        return self.hash_password(password, p), p

    def authenticate_user(self, email, password):
        try:  
            user = resources.User.objects.get(email__iexact=email)
        except resources.User.DoesNotExist, e:
            raise InvalidUser('bad email')
        else:
            if not self.hash_password(password, user.salt) == user.password:
                raise InvalidUser('bad password')
            return user

def hash_password(password, salt):
    m = hashlib.sha256()
    m.update(password)
    m.update(salt)
    return m.hexdigest()
    
def gen_hash_password(password):
    import random
    letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    p = ''
    random.seed()
    for x in range(32):
        p += letters[random.randint(0, len(letters)-1)]
    return hash_password(password, p), p
        
class resource:
    def __init__(self, request):
        self.request = request
        self.res = webob.Response()
        self.qs_dict = urlparse.parse_qs(self.request.query_string)
        self.current_connection_instance = resources.connection._get_connection(reconnect = False)
        self.user = None
        if 'auth_tkt' in self.request.cookies:
            userid = mc.get(str(self.request.cookies['auth_tkt']))
            self.user = resources.User.objects.get(id=userid)
        elif 'auth_tkt' in self.qs_dict:
            userid = mc.get(self.qs_dict['auth_tkt'][0])
            self.user = resources.User.objects.get(id=userid)
    def __call__(self):
        response = {}
        if self.request.urlvars['action'] == 'index':
            response = self.index()
        elif self.request.urlvars['action'] == 'show':
            response = self.show(self.request.urlvars['id'])
        elif self.request.urlvars['action'] == 'update':
            response = self.update(self.request.urlvars['id'])
        elif self.request.urlvars['action'] == 'create':
            response = self.create()
        elif self.request.urlvars['action'] == 'delete':
            response = self.delete(self.request.urlvars['id'])
        if self.user and not 'auth_tkt' in self.qs_dict:
            response['notifications_count'] = self.user.notifications_count             
        self.res.body = json.dumps(response)
        return self.res

class messages(resource):
    def index(self):
        page = self.qs_dict['page'][0] if 'page' in self.qs_dict else 1
        collection = self.qs_dict['collection'][0] if 'collection' in self.qs_dict else 'stampurstamp'
        order = self.qs_dict['order'][0] if 'order' in self.qs_dict else 'ranking'
        get_comments = True if 'more' in self.qs_dict else False
        get_comments = True if 'more' in self.qs_dict else False
        server_func = ""
        
        if collection == 'stampurstamp':
            if self.user:
                server_func = """function(){
    var returnarray = [];
    db.message.find({ to_delete : 0""" + (", body: '' " if get_comments else "") + """ }, { subject : 1, tags : 1, author: 1, body: 1, date_created:1, event_has_time: 1, event_date: 1, event_location:1,ups:1,downs:1,photos:1,num_replies:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(25*(int(page)-1)) + """\").limit(\"""" + str(25) + """\").forEach( function(obj) {
                        obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                        obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                        obj.stamps = []
                        obj.is_author = false;
                        if (obj.author)
                            obj.is_author = db.message.find({_id:obj._id,'author.$id':ObjectId(\"""" + str(self.user.id) + """\")}).count() > 0;
                        obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                        obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                          returnarray.push(obj);
                         } );
    return returnarray;
    }"""
            else:
                server_func = """function(){
    var returnarray = [];
    db.message.find({  to_delete : 0""" + (", body: '' " if get_comments else "") + """ }, { subject : 1, tags : 1, author: 1, body: 1, event_has_time: 1, event_date: 1, event_location:1,date_created:1, ups:1,downs:1,photos:1,num_replies:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(25*(int(page)-1)) + """\").limit(\"""" + str(25) + """\").forEach( function(obj) {
                        obj.uped = false;
                        obj.downed = false;
                        obj.stamps = []
                        obj.is_author = false;
                        obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                        obj.stamps.forEach(function(stamp) {stamp.in_stampbook = false});
                          returnarray.push(obj);
                         } );
    return returnarray;
    }"""
        elif collection == 'stampbook':
            server_func = """function(){
var returnarray = [];
db.message.find({ 'tags': { $in: db.user.findOne({_id:ObjectId(\"""" + str(self.user.id) + """\")},{_id: 0,tag_bucket:1}).tag_bucket } , to_delete : 0 """ + (", body: '' " if get_comments else "") + """}, { subject : 1, event_has_time: 1, event_date: 1, event_location:1,tags : 1, author: 1, body: 1, date_created:1, ups:1,downs:1,photos:1,num_replies:1,author:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(25*(int(page)-1)) + """\").limit(\"""" + str(25) + """\").forEach( function(obj) {
                    obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                    obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                    obj.stamps = [];
                    obj.is_author = false;
                    if (obj.author)
                        obj.is_author = db.message.find({_id:obj._id,'author.$id':ObjectId(\"""" + str(self.user.id) + """\")}).count() > 0;
                    obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                    obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                      returnarray.push(obj);
                     } );
return returnarray;
}"""
        elif collection == 'saved':
            server_func = """function(){
var returnarray = [];
var boxed_ids = [];
db.user.findOne({_id:ObjectId(\"""" + str(self.user.id) + """\")},{_id: 0,boxed_messages:1}).boxed_messages.forEach(
    function(boxed_ref) {
        boxed_ids.push(boxed_ref.$id)
        });
db.message.find({ '_id': { $in: boxed_ids } , to_delete : 0 """ + (", body: '' " if get_comments else "") + """}, { subject : 1, tags : 1, author: 1, event_has_time: 1, event_date: 1, event_location:1,body: 1, date_created:1, ups:1,downs:1,photos:1,num_replies:1,author:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(25*(int(page)-1)) + """\").limit(\"""" + str(25) + """\").forEach( function(obj) {
                    obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                    obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                    obj.stamps = [];
                    obj.is_author = false;
                    if (obj.author)
                        obj.is_author = db.message.find({_id:obj._id,'author.$id':ObjectId(\"""" + str(self.user.id) + """\")}).count() > 0;
                    obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch());});
                    obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                      returnarray.push(obj);
                     } );
return returnarray;
}"""
        elif collection == 'sent':
            print str(self.user.id)
            server_func = """function(){
var returnarray = [];
db.message.find({ 'author.$id': ObjectId(\"""" + str(self.user.id) + """\"), to_delete : 0 """ + (", body: '' " if get_comments else "") + """}, { subject : 1, tags : 1, author: 1, event_has_time: 1, event_date: 1, event_location:1,body: 1, date_created:1, ups:1,downs:1,photos:1,num_replies:1,author:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(25*(int(page)-1)) + """\").limit(\"""" + str(25) + """\").forEach( function(obj) {
                    obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                    obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                    obj.stamps = [];
                    obj.is_author = false;
                    if (obj.author != null)
                        obj.is_author = db.message.find({_id:obj._id,'author.$id':ObjectId(\"""" + str(self.user.id) + """\")}).count() > 0;
                    obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                    obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                      returnarray.push(obj);
                     } );
return returnarray;
}"""
        
        
        messages = self.current_connection_instance.soapboxdb.eval(server_func)
        
        message_array = []
        for message in messages:
            for stamp in message['stamps']:
                stamp['id'] = str(stamp['_id'])
                try:
                    stamp['num_users'] = stamp['numUsers']
                    
                except KeyError, e:
                    stamp['num_users'] = 1
                del stamp['_id']
                del stamp['_cls']
                del stamp['_types']
                try:
                    if stamp['tag_type'] == 'user':
                        if not 'stamp_image' in stamp:
                            stamp['stamp_image'] = 'personal_stamp_bkground'
                        pass
                    else:
                        stamp['tag_type'] = 'public'
                except KeyError, e:
                    stamp['tag_type'] = 'public'    
                if not 'stamp_image' in stamp:
					stamp['stamp_image'] = 'general_stamp_bkground'
                stamp['type'] = stamp['tag_type']
                
                if stamp['stamp_image'] == 'staff_stamp_bkground':
                    stamp['type'] = 'staff'
                    
                if stamp['stamp_image'] == 'stampurstamp_sel':
                    stamp['type'] = 'stampurstamp'
                
                del stamp['tag_type']
                stamp['description'] = stamp['toolTip']
            message_array.append({
                    'id':str(message['_id']),
                    'body':message['body'][:200],
                    'subject':message['subject'],
                    'timestamp':message['date_created'].isoformat(),
                    'formatted_timestamp':message['date_created'].strftime("%b. %d"),
                    'is_event': True if 'event_date' in message else False,
                    'event_date': message['event_date'].strftime("%B %d, %Y") if 'event_date' in message else None,
                    'event_time': message['event_date'].strftime('%I:%M%p').lower() if 'event_has_time' in message and message['event_has_time'] else None,
                    'event_has_time': True if 'event_has_time' in message and message['event_has_time'] else False,
                    'event_location': message['event_location'] if 'event_location' in message and message['event_location'] != '' else None,
                    'uped':message['uped'],
                    'downed':message['downed'],
                    'photos':[{'photo': photo} for photo in message['photos'][:1 if get_comments else 2]],
                    'score':message['ups'] - message['downs'],
                    'num_replies':message['num_replies'],
                    'stamps':message['stamps'],
                    'is_author':message['is_author']
                    })			
        if len(message_array) == 0:
            message_array.append({
                    'id':'4dd070247392d259a9000000',
                    'body':"""Collect stamps to follow your interests!  Select "My Stampbook" to filter messages by just the stamps you have collected.

See "About" to learn how it all works."""[:300],
                    'subject':'Welcome to Stampur!',
                    'timestamp':'',
                    'formatted_timestamp':'Just now',
                    'date':'',
                    'ups':1,
                    'title':'Welcome to Stampur!',
                    'downs':0,
                    'uped':False,
                    'downed':False,
                    'photos':[],
                    'score':1,
                    'num_replies':1,
                    'stamps':[],
                    'is_author':False
                    })
        return {'message_array':message_array}
        
    def show(self, id):
        message = resources.Message.objects.get(id=id)
        private_comments = []
        if self.user:
            if self.user == message.author:
                for comment_child in message.private_comments:
                    comment_child.private_with = 'Hidden User' if comment_child.anonymous else comment_child.author.personal_tag.label
                    private_comments.append(to_comment_object(comment_child))
            else:
                for comment_child in message.private_comments:
                    if self.user == comment_child.author:
                        comment_child.private_with = 'the OP'
                        private_comments.append(to_comment_object(comment_child))
        #print message.author.email
        return {
        'id':str(message.id),
        'body':message.body,
        'subject':message.subject,
        'timestamp':message.date_created.isoformat(),
        'is_event': True if 'event_date' in message else False,
        'event_date': message['event_date'].strftime("%B %d, %Y") if 'event_date' in message else None,
        'event_time': message['event_date'].strftime('%I:%M%p').lower() if 'event_has_time' in message and message['event_has_time'] else None,
        'event_has_time': True if 'event_has_time' in message and message['event_has_time'] else False,
        'event_location': message['event_location'] if 'event_location' in message and message['event_location'] != '' else None,
        'date':message.date_created.strftime("%b. %d").lower(),
        'ups':message.ups,
        'title':message.subject,
        'downs':message.downs,
        'saved':self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'boxed_messages.$id':message.id}).count() > 0 if self.user else False,
        'uped':self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'uped_messages.$id':message.id}).count() > 0 if self.user else False,
        'downed':self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'downed_messages.$id':message.id}).count() > 0 if self.user else False,
        'private_comments':private_comments,
        'comments':[to_comment_object(comment_child, self.user if self.user else None) for comment_child in message.comments],
        'photos':[{'photo': photo} for photo in message['photos']],
        'score':message.ups - message.downs,
        'num_replies':message.num_replies,
        'stamps':[to_stamp_object(tag, self.user) for tag in message.tags],
        'is_author':self.user == message.author if self.user else False
        }
    
    def create(self):
        data = json.loads(self.request.body)
        print data
        if 'title' in data and 'body' in data and 'stampids' in data:
            epoch = datetime.datetime(1970, 1, 1)
            message = resources.Message()
            message.body = bleach.linkify(data['body'])
            message.subject = bleach.linkify(data['title'])
            if 'photos' in data:
                message.photos = data['photos']
                
            for stampid in data['stampids']:
                if stampid == 'Personal':
                    message.tags.append(self.user.personal_tag)
                elif stampid == 'Stampur':
                    message.tags.append(resources.Tag.objects.get(label='Public'))
                else:
                    stamp_to_add = resources.Tag.objects.get(id=stampid)
                    if stamp_to_add.tag_permission != 2 or stampid == '4e4de6727392d20ff5000001':
                        message.tags.append(stamp_to_add)
            message.ups = 1
            print data
            if 'event_date' in data:
                message.event_date = datetime.datetime.strptime(data['event_date'], '%m/%d/%Y')
                print message.event_date
            if 'event_location' in data:
                message.event_location = data['event_location']
            if 'event_time' in data and data['event_time'] != '':
                print data['event_time']
                event_time = datetime.datetime.strptime(data['event_time'], '%I:%M %p').time()
                print event_time
                message.event_date = message.event_date.replace(hour=event_time.hour, minute=event_time.minute)
                message.event_has_time = True
                print message.event_date
                print message.event_has_time
            message.ranking = get_ranking(message)
            BAD_CHARS = ".!?,\'\""
            words = [ word.strip(BAD_CHARS) for word in message.body.strip().split() if len(word) > 2 ]
            word_freq = {}
            for word in words :
                word_freq[word] = word_freq.get(word, 0) + 1
            tx = [ (v, k) for (k, v) in word_freq.items()]
            tx.sort(reverse=True)
            word_freq_sorted = [ (k, v) for (v, k) in tx ]
            for term_pair in word_freq_sorted:
                searchterm = resources.SearchTerm()
                searchterm.term = term_pair[0]
                searchterm.weight = term_pair[1]
                message.terms.append(searchterm)
            
            message.save()
            print message.event_date
            if self.user:
                self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$set' : { 'author' : bson.dbref.DBRef('user',self.user.id) } })
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'uped_messages' : bson.dbref.DBRef('message',message.id) } })
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'sent_messages' : {     "message" : bson.dbref.DBRef('message',message.id),     "_types" : [     "Notification" ],     "_cls" : "Notification",     "notification_count" : 0 }} })

        return {}
        
    def delete(self, id):
        message = resources.Message.objects.get(id=id)
        if self.user:
            if self.user == message.author:
                self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$set' : { 'to_delete' : 1 } })
                return {}
        self.res.status = 403
        return {}
        
        
class comments(resource):
    def index(self):
        message = resources.Message.objects.get(id=self.request.urlvars['message_id'])
        return [to_comment_object(comment) for comment in message.comments]
        
    def show(self, id):
        return to_comment_object(resources.Comment.objects.get(id=id))
        
    def create(self):
        message_id = self.request.urlvars['message_id']
        message = resources.Message.objects.get(id=message_id)
        data = json.loads(self.request.body)
        comment = resources.Comment()
        comment.body = bleach.linkify(data['add_reply']['body'])
        #print comment.body
        comment.anonymous = True
        if 'anonymous' in data['add_reply']:
            comment.anonymous = data['add_reply']['anonymous']
        comment.private = True
        if 'private' in data['add_reply']:
            comment.private = data['add_reply']['private']
        comment.save()
        self.current_connection_instance.soapboxdb.comment.update({ '_id':comment.id},{ '$set' : { 'author' : bson.dbref.DBRef('user',self.user.id),'parent_message' : bson.dbref.DBRef('message',message.id) } })

        if 'commentid' in data['add_reply']:
            parent_comment = resources.Comment.objects.get(id=data['add_reply']['commentid'])
            self.current_connection_instance.soapboxdb.comment.update({ '_id':parent_comment.id},{ '$push' : { 'comments' : bson.dbref.DBRef('comment',comment.id) } })
            self.current_connection_instance.soapboxdb.comment.update({ '_id':comment.id},{ '$set' : { 'parent_comment' : bson.dbref.DBRef('comment',parent_comment.id) } })
            if not parent_comment.author == self.user:
                self.current_connection_instance.soapboxdb.user.update({ '_id':parent_comment.author.id,'sent_messages.comment':bson.dbref.DBRef('comment',parent_comment.id)},{ '$inc' : { 'sent_messages.$.notification_count' : 1, 'notifications_count': 1} })
            if not comment.private:
                self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'num_replies' : 1 } })
        elif comment.private:
            self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$push' : { 'private_comments' : bson.dbref.DBRef('comment',comment.id) } })
        else:
            self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'num_replies' : 1 },'$push' : { 'comments' : bson.dbref.DBRef('comment',comment.id) } })
        

        self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'sent_messages' : { "comment" : bson.dbref.DBRef('comment',comment.id), "_types" : ["Notification"], "_cls" : "Notification", "notification_count" : 0 }} })
        
        if not message.author == self.user:
            try:
                self.current_connection_instance.soapboxdb.user.update({ '_id':message.author.id,'sent_messages.message':bson.dbref.DBRef('message',message.id)},{ '$inc' : { 'sent_messages.$.notification_count' : 1, 'notifications_count': 1} })
            except Exception, e:
                pass
        return {}

    def delete(self, id):
        comment = resources.Comment.objects.get(id=id)
        if (comment.author == self.user):
            self.current_connection_instance.soapboxdb.comment.update({ '_id':comment.id},{ '$set' : { 'body' : '' } })
        return {}





class collections(resource):
    def index(self):
        return {}
        
    def show(self, id):
        
        
        if 'show_stamps' in self.qs_dict:
            collection = resources.StampCollection.objects.get(id=id)
            return {'stamp_array':[to_stamp_object(stamp, self.user) for stamp in collection.stamps]}
        
        page = self.qs_dict['page'][0] if 'page' in self.qs_dict else 1
        order = self.qs_dict['order'][0] if 'order' in self.qs_dict else 'ranking'
        if self.user:
            server_func = """function(){
                var returnarray = [];
                db.message.find({ 'tags': { $in: db.stamp_collection.findOne({_id:ObjectId(\"""" + str(id) + """\")},{_id: 0,stamps:1}).stamps } , to_delete : 0 }, { subject : 1, tags : 1, author: 1, body: 1, date_created:1, ups:1,downs:1,photos:1,num_replies:1,author:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(15*(int(page)-1)) + """\").limit(\"""" + str(15) + """\").forEach( function(obj) {
                                    obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                                    obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                                    obj.stamps = [];
                                    obj.is_author = false;
                                    if (obj.author)
                                    obj.is_author = obj.author._id == ObjectId(\"""" + str(self.user.id) + """\");
                                    obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                                    obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                                      returnarray.push(obj);
                                     } );
                return returnarray;
                }"""
        else:
            server_func = """function(){
                var returnarray = [];
                db.message.find({ 'tags': { $in: db.stamp_collection.findOne({_id:ObjectId(\"""" + str(id) + """\")},{_id: 0,stamps:1}).stamps } , to_delete : 0 }, { subject : 1, tags : 1, author: 1, body: 1, date_created:1, ups:1,downs:1,photos:1,num_replies:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(15*(int(page)-1)) + """\").limit(\"""" + str(15) + """\").forEach( function(obj) {
                                    obj.uped = false;
                                    obj.downed = false;
                                    obj.stamps = []
                                    obj.is_author = false;
                                    if (obj.author)
                                    obj.is_author = false;
                                    obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                                    obj.stamps.forEach(function(stamp) {stamp.in_stampbook = false});
                                      returnarray.push(obj);
                                     } );
                return returnarray;
                }"""
        messages = self.current_connection_instance.soapboxdb.eval(server_func)
        
        message_array = []
        for message in messages:
            for stamp in message['stamps']:
                stamp['id'] = str(stamp['_id'])
                stamp['num_users'] = stamp['numUsers']
                del stamp['_id']
                del stamp['_cls']
                del stamp['_types']
                del stamp['numUsers']
                if stamp['tag_type'] == 'user':
                    if not 'stamp_image' in stamp:
                        stamp['stamp_image'] = 'personal_stamp_bkground'
                    pass
                else:
                    stamp['tag_type'] = 'public'
                    
                if not 'stamp_image' in stamp:
					stamp['stamp_image'] = 'general_stamp_bkground'
                stamp['type'] = stamp['tag_type']
                del stamp['tag_type']
                #stamp['num_messages'] = len(resources.Message.objects(tags=stamp))
                
                if stamp['stamp_image'] == 'staff_stamp_bkground':
                    stamp['type'] = 'staff'
                if stamp['stamp_image'] == 'stampurstamp_sel':
                    stamp['type'] = 'stampurstamp'
                stamp['description'] = stamp['toolTip']
            message_array.append({
                    'id':str(message['_id']),
                    'body':message['body'][:300].replace('\n','<br>'),
                    'subject':message['subject'],
                    'timestamp':message['date_created'].isoformat(),
                    'formatted_timestamp':message['date_created'].strftime("%b. %d"),
                    'date':message['date_created'].strftime("%b. %d").lower(),
                    'ups':message['ups'],
                    'title':message['subject'],
                    'downs':message['downs'],
                    'uped':message['uped'],
                    'downed':message['downed'],
                    'photos':[{'photo': photo} for photo in message['photos']],
                    'score':message['ups'] - message['downs'],
                    'num_replies':message['num_replies'],
                    'stamps':message['stamps'],
                    'is_author':message['is_author']
                    })
        
        return {'message_array':message_array}
    
    def update(self, id):
        data = json.loads(self.request.body)
        collection = resources.StampCollection.objects.get(id=id)
        if 'add_stamp' in data:
            stamp = resources.Tag.objects.get(id=data['add_stamp'])
            if stamp not in collection.stamps:
                self.current_connection_instance.soapboxdb.stamp_collection.update({ '_id':collection.id},{ '$push' : { 'stamps' : bson.dbref.DBRef('tag',stamp.id) } })
            else:
                self.res.status = 403
        elif 'remove_stamp' in data:
            stamp = resources.Tag.objects.get(id=data['remove_stamp'])
            if stamp in collection.stamps:
                self.current_connection_instance.soapboxdb.stamp_collection.update({ '_id':collection.id},{ '$pull' : { 'stamps' : {'$id': stamp.id} } })
            else:
                self.res.status = 403
        return {'info':"see status"}
    
    def create(self):
        data = json.loads(self.request.body)
        if 'name' in data:
            collection = resources.StampCollection()
            collection.name = data['name']
            collection.save()
            self.current_connection_instance.soapboxdb.stamp_collection.update({ '_id':collection.id},{ '$set' : { 'owner' : bson.dbref.DBRef('user',self.user.id) } })
            self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'collections' : bson.dbref.DBRef('stamp_collection',collection.id) } })
        return {}
        
    def delete(self, id):
        collection = resources.StampCollection.objects.get(id=id)
        print collection.name
        print collection.owner
        if self.user:
            self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'collections' : bson.dbref.DBRef('stamp_collection',collection.id) } })
        return {}
        
class stamps(resource):
    def index(self):
        grouping = self.qs_dict['grouping'][0] if 'grouping' in self.qs_dict else None
        postable = self.qs_dict['postable'][0] if 'postable' in self.qs_dict else None
        query = self.qs_dict['query'][0] if 'query' in self.qs_dict else None
        if grouping == 'all':
            stamps = {'academics':[],'top':[],'locations':[],'people':[],'general':[],'places':[],'interests':[],'groups':[]}
            if self.user and not 'auth_tkt' in self.qs_dict:
                stamps['my_stamps'] = []
                for stamp in sorted(self.user.tag_bucket, key=lambda stamp: stamp.label):
                    stamps['my_stamps'].append(to_stamp_object(stamp,self.user))
            general_stamps = resources.Tag.objects(tag_type='Default').order_by("-numUsers")
            for stamp in general_stamps:
                stamps['general'].append(to_stamp_object(stamp, self.user))
            places_stamps = resources.Tag.objects(Q(tag_type='Locations') & Q(numUsers__gt=5)).order_by("+label")
            for stamp in places_stamps:
                stamps['places'].append(to_stamp_object(stamp, self.user))
            interests_stamps = resources.Tag.objects(Q(tag_type='Social') & Q(numUsers__gt=8)).order_by("+label")
            for stamp in interests_stamps:
                stamps['interests'].append(to_stamp_object(stamp, self.user))
            groups_stamps = resources.Tag.objects(tag_type='Orgs').order_by("+label")
            for stamp in groups_stamps:
                stamps['groups'].append(to_stamp_object(stamp, self.user))
            groups_stamps = resources.Tag.objects().order_by("-numUsers")[0:16]
            for stamp in groups_stamps:
                stamps['top'].append(to_stamp_object(stamp, self.user))
            academics_stamps = resources.Tag.objects(category='academics').order_by('+label')
            for stamp in academics_stamps:
                stamps['academics'].append(to_stamp_object(stamp, self.user))
            if postable != 'true':
                people_stamps = resources.Tag.objects(tag_type='user').order_by("-numUsers")[0:25]
                for stamp in people_stamps:
                    if '@' not in stamp.label:
                        stamps['people'].append(to_stamp_object(stamp, self.user))
            return stamps
        elif grouping == 'stampbook':
            stamps = {'my_stamps':[]}
            if self.user is not None:
                for stamp in sorted(self.user.tag_bucket, key=lambda stamp: stamp.label):
                    stamps['my_stamps'].append(to_stamp_object( p,self.user))
            return stamps
        if query:
            search_stamps = resources.Tag.objects(Q(label__icontains=query)).order_by("-numUsers")
            while len(search_stamps) == 0:
                query = query[0:-1]
                search_stamps = resources.Tag.objects(Q(label__icontains=query)).order_by("-numUsers")
            return {'stamp_array':[to_stamp_object(stamp, self.user) for stamp in search_stamps]}
        return {'stamp_array':[to_stamp_object(stamp, self.user) for stamp in resources.Tag.objects(tag_permission=0).order_by("+label")]}
        
    def show(self, stampid):
        try:
            stamp = resources.Tag.objects.get(id=stampid)
        except Exception, e:    
            try:
                stamp = resources.Tag.objects.get(label=stampid)
            except Exception, e:
                try:
                    stamp = resources.Tag.objects.get(label=stampid.replace('_',' '))
                except Exception, e:
                    try:
                        stamp = resources.Tag.objects.get(label__iexact=stampid.replace('_',' '))
                    except Exception, e:
                        try:
                            stamp = resources.Tag.objects.get(label__iexact=stampid.replace('_','/'))
                        except Exception, e:
                            return {"stamp":"bad id numberinner"}
        if not stamp:
            return {"stamp":"bad id number"}
        stamp_photos = resources.Message.objects(Q(tags=stamp) & Q(photos__not__size=0 )).order_by("-ups")[:18]
        message_photos = [message.photos for message in stamp_photos]
        resp_photos = []
        for message_photo in message_photos:
            resp_photos = resp_photos + message_photo 
        if 'page' in self.qs_dict:
            return_stamp = stamp
            page = self.qs_dict['page'][0]
            order = self.qs_dict['order'][0] if 'order' in self.qs_dict else 'ranking'
            count = 30 if 'more' in self.qs_dict else 10
            get_comments = True if 'more' in self.qs_dict else False
            
            
            if self.user and get_comments:
                server_func = """function(){
    var returnarray = [];
    db.message.find({ 'tags.$id': ObjectId(\"""" + str(stamp.id) + """\")""" + (", body: '' " if get_comments else "") + """ }, { subject : 1, tags : 1, author: 1, body: 1, event_has_time: 1, event_date: 1, event_location:1, date_created:1, ups:1,downs:1,photos:1,num_replies:1,comments:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(count*(int(page)-1)) + """\").limit(\"""" + str(count) + """\").forEach( function(obj) {
                        obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                        obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                        obj.stamps = []
                        obj.is_author = false;
                        if (obj.author)
                        obj.is_author = obj.author._id == ObjectId(\"""" + str(self.user.id) + """\");
                        
                        var comments_fetched = [];
                        obj.comments.forEach(function(comment)
                        {comments_fetched.push(comment.fetch());});
                        obj.comments = comments_fetched;
                        
                        obj.comments.forEach(function(comment)
                        {
                        comment.author = db.user.find({email:'kyle@stampur.com'},{personal_tag:1,comment_notifications:0,downed_messages:0,uped_messages:0});
                        //comment.author = db.user.find({_id:comment.author.$id},{personal_tag:1,comment_notifications:0,downed_messages:0,uped_messages:0});
                        //comment.author.personal_tag = comment.author.personal_tag.fetch();
                        });
                        
                        obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                        obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                          returnarray.push(obj);
                         } );
    return returnarray;
    }"""

                print server_func
            elif get_comments:
                server_func = """function(){
    var returnarray = [];
    db.message.find({ 'tags.$id': ObjectId(\"""" + str(stamp.id) + """\")""" + (", body: '' " if get_comments else "") + """ }, { subject : 1, tags : 1, author: 1, body: 1, event_has_time: 1, event_date: 1, event_location:1, date_created:1, ups:1,downs:1,photos:1,num_replies:1,comments:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(count*(int(page)-1)) + """\").limit(\"""" + str(count) + """\").forEach( function(obj) {
                        obj.uped = false;
                        obj.downed = false;
                        obj.stamps = []
                        obj.is_author = false;
                        if (obj.author)
                        obj.is_author = false;
                        
                        var comments_fetched = [];
                        obj.comments.forEach(function(comment)
                        {comments_fetched.push(comment.fetch());});
                        obj.comments = comments_fetched;
                        
                        obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                        obj.stamps.forEach(function(stamp) {stamp.in_stampbook = false});
                          returnarray.push(obj);
                         } );
    return returnarray;
    }"""
            elif self.user:
                server_func = """function(){
    var returnarray = [];
    db.message.find({ 'tags.$id': ObjectId(\"""" + str(stamp.id) + """\") }, { subject : 1, tags : 1, author: 1, body: 1, event_has_time: 1, event_date: 1, event_location:1, date_created:1, ups:1,downs:1,photos:1,num_replies:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(count*(int(page)-1)) + """\").limit(\"""" + str(count) + """\").forEach( function(obj) {
                        obj.uped = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'uped_messages.$id':obj._id}).count() > 0;
                        obj.downed = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'downed_messages.$id':obj._id}).count() > 0;
                        obj.stamps = []
                        obj.is_author = false;
                        if (obj.author)
                        obj.is_author = obj.author._id == ObjectId(\"""" + str(self.user.id) + """\");
                        obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                        obj.stamps.forEach(function(stamp) {stamp.in_stampbook = db.user.find({_id:ObjectId(\"""" + str(self.user.id) + """\"),'tag_bucket.$id':stamp._id}).count() > 0;});
                          returnarray.push(obj);
                         } );
    return returnarray;
    }"""
            else:
                server_func = """function(){
    var returnarray = [];
    db.message.find({ 'tags.$id': ObjectId(\"""" + str(stamp.id) + """\") }, { subject : 1, tags : 1, author: 1, body: 1, event_has_time: 1, event_date: 1, event_location:1, date_created:1, ups:1,downs:1,photos:1,num_replies:1}).sort({""" + str(order) + """: -1}).skip(\"""" + str(count*(int(page)-1)) + """\").limit(\"""" + str(count) + """\").forEach( function(obj) {
                        obj.uped = false;
                        obj.downed = false;
                        obj.stamps = []
                        obj.is_author = false;
                        if (obj.author)
                        obj.is_author = false;
                        obj.tags.forEach(function(stamp) {obj.stamps.push(stamp.fetch({label:1}));});
                        obj.stamps.forEach(function(stamp) {stamp.in_stampbook = false});
                          returnarray.push(obj);
                         } );
    return returnarray;
    }"""
            messages = self.current_connection_instance.soapboxdb.eval(server_func)
            message_array = []
            for message in messages:
                if 'comments' in message:
                    print message['comments']
                for stamp in message['stamps']:
                    stamp['id'] = str(stamp['_id'])
                    try:
                        stamp['num_users'] = stamp['numUsers']
                    
                    except KeyError, e:
                        stamp['num_users'] = 1
                    del stamp['_id']
                    del stamp['_cls']
                    del stamp['_types']
                    try:
                        if stamp['tag_type'] == 'user':
                            if not 'stamp_image' in stamp:
                                stamp['stamp_image'] = 'personal_stamp_bkground'
                            pass
                        else:
                            stamp['tag_type'] = 'public'
                    except KeyError, e:
                        stamp['tag_type'] = 'public'  
                    if not 'stamp_image' in stamp:
                        stamp['stamp_image'] = 'general_stamp_bkground'    
                    
                    stamp['type'] = stamp['tag_type']
                    
                    if stamp['stamp_image'] == 'staff_stamp_bkground':
                        stamp['type'] = 'staff'
                    if stamp['stamp_image'] == 'stampurstamp_sel':
                        stamp['type'] = 'stampurstamp'
                    del stamp['tag_type']
                    stamp['description'] = stamp['toolTip']
                message_array.append({
                        'id':str(message['_id']),
                        'body':message['body'][:300],
                        'subject':message['subject'],
                        'timestamp':message['date_created'].isoformat(),
                        'formatted_timestamp':message['date_created'].strftime("%b. %d"),
                        'is_event': True if 'event_date' in message else False,
                        'event_date': message['event_date'].strftime("%B %d, %Y") if 'event_date' in message else None,
                        'event_time': message['event_date'].strftime('%I:%M%p').lower() if 'event_has_time' in message and message['event_has_time'] else None,
                        'event_has_time': True if 'event_has_time' in message and message['event_has_time'] else False,
                        'event_location': message['event_location'] if 'event_location' in message and message['event_location'] != '' else None,
                        'uped':message['uped'],
                        'downed':message['downed'],
                        #'comments':[to_comment_object_one(comment_child) for comment_child in message['comments']] if 'comments' in message else [],
                        'photos':[{'photo': photo} for photo in message['photos'][:1 if get_comments else 2]],
                        'score':message['ups'] - message['downs'],
                        'num_replies':message['num_replies'],
                        'stamps':message['stamps'],
                        'is_author':message['is_author']
                        })
            return {"stamp":to_stamp_object(return_stamp),"stamp_photos":resp_photos,"message_array":message_array}
        return {"stamp":to_stamp_object(stamp, self.user),"stamp_photos":resp_photos}
    
    def create(self):
        data = json.loads(self.request.body)
        if 'label' in data and 'description' in data:
            print data
            stamp = resources.Tag()
            stamp.location = [34.420830000000002, -119.69819000000001]
            stamp.label = data['label']
            stamp.toolTip = data['description']
            stamp.tag_type = 'general'
            stamp.tag_permission = 0
            if data['external_content']:
                stamp.features.append(resources.StampFeatures.EXTERNAL_FEED)
                stamp.external_url = data['external_url']
                pieces = urlparse.urlparse(data['external_url'])
                if pieces.scheme not in ['http', 'https']:
                    self.res.status = 403
                    return {'json_error':'Invalid external URL!'}
                suggestion_response = feeder.verifyFeed(data['external_url'])
                print suggestion_response
                stamp.save()
                if self.user:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'tag_bucket' : bson.dbref.DBRef('tag',stamp.id) } })

                return suggestion_response
            stamp.save()
            if self.user:
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'tag_bucket' : bson.dbref.DBRef('tag',stamp.id) } })
        return {}
        
class users(resource):
    def index(self):
        return {'error':"can't list all users"}
                
    def show(self, id):
        notifications = self.qs_dict['notifications'][0] if 'notifications' in self.qs_dict else None
        read = self.qs_dict['read'][0] if 'read' in self.qs_dict else None
        if notifications:
            notification_array = []
            if not len(self.user.sent_messages) == 0:
                message_notifications = self.user.sent_messages
                for message_notification in message_notifications:
                    if message_notification.notification_count == 0:
                        continue
                    if message_notification.message is not None:
                        message = message_notification.message
                        notification_array.append({'notification_count':message_notification.notification_count,'type':'message','message':
                        {'id':str(message.id),
                        'subject':message.subject
                        }})
                    else:
                        comment = message_notification.comment
                        try:
                            notification_array.append({'notification_count':message_notification.notification_count,'type':'comment','comment':
                            {'id':str(comment.id),
                            'body':comment.body,
                            'message_id':str(comment.parent_message.id)
                            }})
                        except Exception, e:
                            pass
            return {'notification_array':notification_array}
        elif read:
            current_nots = self.user.notifications_count
            message = resources.Message.objects.get(id=read)
            sub_nots = 0
            for message_notification in self.user.sent_messages:
                if message == message_notification.message:
                    sub_nots = sub_nots + message_notification.notification_count
                if message_notification.comment is not None:
                    if message == message_notification.comment.parent_message:
                        sub_nots = sub_nots + message_notification.notification_count
                        self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id,'sent_messages.comment':bson.dbref.DBRef('comment',message_notification.comment.id)},{ '$set' : { 'sent_messages.$.notification_count' : 0} })
            
            self.current_connection_instance.soapboxdb.user.update({'_id':self.user.id,'sent_messages.message':bson.dbref.DBRef('message',message.id)},{ '$set' : { 'sent_messages.$.notification_count' : 0}})
            self.current_connection_instance.soapboxdb.user.update({'_id':self.user.id},{ '$set' : {'notifications_count':current_nots - sub_nots}})
            return {'new_notifications_count':current_nots - sub_nots}
        elif 'get_photo' in self.qs_dict:
            try:
                photo = self.user.personal_tag.photos[0]
            except Exception, e:
                photo = ''
            return {'photo_url': photo }
        elif 'notifications_count' in self.qs_dict:
            return {'notifications_count':self.user.notifications_count}
            
        collections = []
        try:
            if 'collections' in self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id})[0]:
                db_collections = self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id})[0]['collections']
                for collection in db_collections:
                    collection = resources.StampCollection.objects.get(id=collection.id)
                    collections.append({'name':collection.name,'id':str(collection.id)})
        except Exception, e:
            pass
        return {
                'email':self.user.email,
                'location':self.user.location,
                'username':self.user.personal_tag.label,
                'stamp_image':self.user.personal_tag.stamp_image,
                'stamp_description':self.user.personal_tag.toolTip,
                'notifications_count':self.user.notifications_count,
                'collections':collections
            }
            
    def update(self, id):
        data = json.loads(self.request.body)
        message = None
        if 'add_stamp' in data:
            stamp = resources.Tag.objects.get(id=data['add_stamp'])
            if stamp not in self.user.tag_bucket:
                self.current_connection_instance.soapboxdb.tag.update({ '_id':stamp.id},{ '$inc' : { 'numUsers' : 1 } })
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'tag_bucket' : bson.dbref.DBRef('tag',stamp.id) } })
            else:
                self.res.status = 403
        elif 'remove_stamp' in data:
            stamp = resources.Tag.objects.get(id=data['remove_stamp'])
            if stamp in self.user.tag_bucket:
                self.current_connection_instance.soapboxdb.tag.update({ '_id':stamp.id},{ '$inc' : { 'numUsers' : -1 } })
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'tag_bucket' : {'$id': stamp.id} } })
            else:
                self.res.status = 403
        elif 'uped' in data:
            message = resources.Message.objects.get(id=data['messageid'])
            if data['uped']:
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'downed_messages.$id':message.id}).count() > 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'downed_messages' : bson.dbref.DBRef('message',message.id) } })
                    self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'downs' : -1 } })
                    message.downs = message.downs - 1
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'uped_messages.$id':message.id}).count() == 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'uped_messages' : bson.dbref.DBRef('message',message.id) } })
                    self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'ups' : 1 } })
                    message.ups = message.ups + 1
            else:
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'uped_messages.$id':message.id}).count() > 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'uped_messages' : bson.dbref.DBRef('message',message.id) } })
                    self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'ups' : -1 } })
                    message.ups = message.ups - 1
            self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$set' : { 'ranking' : get_ranking(message) } })
        elif 'downed' in data:
            message = resources.Message.objects.get(id=data['messageid'])
            if data['downed']:
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'uped_messages.$id':message.id}).count() > 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'uped_messages' : bson.dbref.DBRef('message',message.id) } })
                    self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'ups' : -1 } })
                    message.ups = message.ups - 1
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'downed_messages.$id':message.id}).count() == 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'downed_messages' : bson.dbref.DBRef('message',message.id) } })
                    self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'downs' : 1 } })
                    message.downs = message.downs + 1
            else:
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'downed_messages.$id':message.id}).count() > 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'downed_messages' : bson.dbref.DBRef('message',message.id) } })
                    self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'downs' : -1 } })
                    message.downs = message.downs - 1
            self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$set' : { 'ranking' : get_ranking(message) } })
        elif 'saved' in data:
            message = resources.Message.objects.get(id=data['messageid'])
            if data['saved']:
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'boxed_messages.$id':message.id}).count() == 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'boxed_messages' : bson.dbref.DBRef('message',message.id) } })
            else:
                if self.current_connection_instance.soapboxdb.user.find({ '_id':self.user.id, 'boxed_messages.$id':message.id}).count() > 0:
                    self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$pull' : { 'boxed_messages' : bson.dbref.DBRef('message',message.id) } })
        elif 'new_pass' in data:
            self.user.password, self.user.salt = gen_hash_password(data['new_pass'])
            self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$set' : { 'password' : self.user.password, 'salt': self.user.salt } })
        elif 'new_pic' in data:
            self.user.password, self.user.salt = gen_hash_password(data['new_pass'])
            self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$set' : { 'password' : self.user.password, 'salt': self.user.salt } })
        return {'info':"see status",'score': (message.ups - message.downs) if message is not None else 0}
        
def controller_dispatcher(request):
    return eval(request.urlvars['controller']+'(request)')()

def app(environ, start_response):
    req = webob.Request(environ)
    if 'controller' in req.urlvars:
        res = controller_dispatcher(req)
        return res(environ, start_response)
    return webob.Response(body="Hmmm, error?")(environ, start_response)

application = routes.middleware.RoutesMiddleware(app, routes_map)

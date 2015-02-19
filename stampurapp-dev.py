import os, sys
sys.path.append('/srv/www/stampurapp')
os.environ['PYTHON_EGG_CACHE'] = '/srv/www/.python-egg'

import resources

import json
import hashlib
import uuid
import urlparse
import datetime
import math

import pylibmc
import bleach
import webob
import webob.exc
import bson

import routes
import routes.middleware
from mongoengine import *

mc = pylibmc.Client(['127.0.0.1:11211'], binary=True, behaviors={"tcp_nodelay": True})

map = routes.Mapper()


#top level photos
map.resource("stamp", "stamps", path_prefix="/json")
map.resource("user", "users", path_prefix="/json")
map.resource("message", "messages", path_prefix="/json")
map.resource("comment", "comments", path_prefix="/json/messages/{message_id}")

map.connect(None, "/mediaload/{action}", controller="media")
map.connect(None, "/auth/{action}", controller="auth")
map.connect(None, "/{resource}/{id}", controller="root")
map.connect(None, "/{resource}", controller="root")
map.connect(None, "/", controller="root")


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
        'comments':[to_comment_object(comment_child) for comment_child in message.comments],
        'photos':message.photos,
        'score':message.ups - message.downs,
        'num_replies':message.num_replies,
        'stamps':[to_stamp_object(tag, user) for tag in message.tags],
        'is_author':user == message.author if user else False
        }

def to_stamp_object(stamp, user=None):
    return {
        'id':str(stamp.id),
        'label':stamp.label,
        "photo":stamp.photos,
        'type':stamp.tag_type,
        'location':stamp.location,
        'category':stamp.category,
        'description':stamp.toolTip,
        'stamp_image':stamp.stamp_image,
        'in_stampbook':stamp in user.tag_bucket if user else None,
        'num_users':stamp.numUsers
        }
        
def to_comment_object(comment):
    return {
        'id':str(comment.id), 
        'comments':[to_comment_object(comment_child) for comment_child in comment.comments], 
        'timestamp':comment.date_created.isoformat(),
        'date':comment.date_created.strftime("%b. %d").lower(),
        'body':comment.body,
        'score':comment.ups-comment.downs,
        'author_id':None if comment.anonymous else str(comment.author.personal_tag.id),
        'author':None if comment.anonymous else comment.author.personal_tag.label
        }

def get_ranking(message):
    epoch = datetime.datetime(1970, 1, 1)
    td = message.date_created - epoch
    seconds = td.days * 86400 + td.seconds + (float(td.microseconds) / 1000000) - 1134028003
    score = message.ups - message.downs
    score = score + (2 * message.num_replies)
    order = 1.8 * math.log(max(abs(score), 1), 10)
    sign = 1 if score > 0 else -1 if score < 0 else 0
    return round(order + sign * seconds / 45000, 7)

class root:
    def __init__(self, request):
        self.request = request
        self.res = webob.Response()
        self.qs_dict = urlparse.parse_qs(self.request.query_string)
    def __call__(self):
        loggedin = False
        location = None
        page = None
        resource = None
        bad_login = None
        id = None
        print self.request.url
        if 'auth_tkt' in self.request.cookies:
            loggedin = True
            resource = 'stampurstamp'
        else:
            resource = 'stampurstamp'
        if 'resource' in self.request.urlvars:
            resource = self.request.urlvars['resource']
        if 'page' in self.qs_dict:
            page = self.qs_dict['page'][0]
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
        self.res.body = json.dumps({'loggedin':loggedin,'action':action,'resource':resource,'page':page,'id':id,'bad_login':bad_login})
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
        f = open('/srv/www/media/' + filename, 'a')
        f.write(self.request.body)
        f.close()
        f = open('/srv/www/media/thumbs/' + filename, 'a')
        f.write(self.request.body)
        f.close()
        os.system("mogrify -resize 256x256 /srv/www/media/thumbs/" + filename)
        return filename
    

class InvalidUser(Exception):
    pass


class auth:
    def __init__(self, request):
        self.request = request
        self.res = webob.exc.HTTPFound(location="/")
        
    def __call__(self):
        if self.request.urlvars['action'] == 'login_post':
            self.login_post()
        elif self.request.urlvars['action'] == 'logout':
            self.logout()
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
        if self.user:
            response['notifications_count'] = self.user.notifications_count
        self.res.body = json.dumps(response)
        return self.res

class messages(resource):
    def index(self):
        page = self.qs_dict['page'][0] if 'page' in self.qs_dict else 1
        collection = self.qs_dict['collection'][0] if 'collection' in self.qs_dict else 'stampurstamp'
        order = self.qs_dict['order'][0] if 'order' in self.qs_dict else 'ranking'
        if collection == 'stampurstamp':
            messages = resources.Message.objects(Q(tags__in=[resources.Tag.objects().get(tag_type='Public')]) & Q(to_delete__ne=1)).order_by("-" + order)[15*(int(page)-1):15*(int(page)-1)+15]
        elif collection == 'stampbook':
            messages = resources.Message.objects(Q(tags__in=self.user.tag_bucket) & Q(to_delete__ne=1) ).order_by("-" + order)[15*(int(page)-1):15*(int(page)-1)+15]
        elif collection == 'saved':
            messages = resources.Message.objects(id__in=[message.id for message in self.user.boxed_messages]).order_by("-" + order)[15*(int(page)-1):15*(int(page)-1)+15]
        elif collection == 'sent':
            messages = resources.Message.objects(Q(author=self.user) & Q(to_delete__ne=1)).order_by("-ranking")[15*(int(page)-1):15*(int(page)-1)+15]
        
        return {'messages_array':[to_message_object(message) for message in messages]}
        
    def show(self, id):
        return to_message_object_wstamps(resources.Message.objects.get(id=id))
    
    def create(self):
        data = json.loads(self.request.body)
        if 'title' in data and 'body' in data and 'stampids' in data:
            epoch = datetime.datetime(1970, 1, 1)
            message = resources.Message()
            message.body = bleach.linkify(data['body'])
            message.subject = bleach.linkify(data['title'])
            message.photos = data['photos']
            for stampid in data['stampids']:
                if stampid == 'Personal':
                    message.tags.append(self.user.personal_tag)
                elif stampid == 'Stampur':
                    message.tags.append(resources.Tag.objects.get(label='Public'))
                else:
                    stamp_to_add = resources.Tag.objects.get(id=stampid)
                    if stamp_to_add.tag_permission != 2:
                        message.tags.append(stamp_to_add)                    
            message.ups = 1
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
            if self.user:
                self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$set' : { 'author' : bson.dbref.DBRef('user',self.user.id) } })
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'uped_messages' : bson.dbref.DBRef('message',message.id) } })
                self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'sent_messages' : {     "message" : bson.dbref.DBRef('message',message.id),     "_types" : [     "Notification" ],     "_cls" : "Notification",     "notification_count" : 0 }} })

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
        
        comment.anonymous = True
        if 'anonymous' in data['add_reply']:
            comment.anonymous = data['add_reply']['anonymous']
        comment.save()
        self.current_connection_instance.soapboxdb.comment.update({ '_id':comment.id},{ '$set' : { 'author' : bson.dbref.DBRef('user',self.user.id),'parent_message' : bson.dbref.DBRef('message',message.id) } })

        if 'commentid' in data['add_reply']:
            parent_comment = resources.Comment.objects.get(id=data['add_reply']['commentid'])
            self.current_connection_instance.soapboxdb.comment.update({ '_id':parent_comment.id},{ '$push' : { 'comments' : bson.dbref.DBRef('comment',comment.id) } })
            self.current_connection_instance.soapboxdb.comment.update({ '_id':comment.id},{ '$set' : { 'parent_comment' : bson.dbref.DBRef('comment',parent_comment.id) } })
            if not parent_comment.author == self.user:
                self.current_connection_instance.soapboxdb.user.update({ '_id':parent_comment.author.id,'sent_messages.comment':bson.dbref.DBRef('comment',parent_comment.id)},{ '$inc' : { 'sent_messages.$.notification_count' : 1, 'notifications_count': 1} })
            self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'num_replies' : 1 } })
        else:
            self.current_connection_instance.soapboxdb.message.update({ '_id':message.id},{ '$inc' : { 'num_replies' : 1 },'$push' : { 'comments' : bson.dbref.DBRef('comment',comment.id) } })
        

        self.current_connection_instance.soapboxdb.user.update({ '_id':self.user.id},{ '$push' : { 'sent_messages' : { "comment" : bson.dbref.DBRef('comment',comment.id), "_types" : ["Notification"], "_cls" : "Notification", "notification_count" : 0 }} })
        
        if not message.author == self.user:
            self.current_connection_instance.soapboxdb.user.update({ '_id':message.author.id,'sent_messages.message':bson.dbref.DBRef('message',message.id)},{ '$inc' : { 'sent_messages.$.notification_count' : 1, 'notifications_count': 1} })
                    
        return {}


        
class stamps(resource):
    def index(self):
        grouping = self.qs_dict['grouping'][0] if 'grouping' in self.qs_dict else None
        postable = self.qs_dict['grouping'][0] if 'grouping' in self.qs_dict else None
        query = self.qs_dict['query'][0] if 'query' in self.qs_dict else None
        if grouping == 'catagory':
            stamps = {'academics':[],'my_stamps':[],'top':[],'locations':[],'people':[],'general':[],'places':[],'interests':[],'groups':[]}
            if self.user:
                for stamp in sorted(self.user.tag_bucket, key=lambda stamp: stamp.label):
                    stamps['my_stamps'].append(to_stamp_object(stamp,self.user))
            general_stamps = resources.Tag.objects(tag_type='Default').order_by("-numUsers")
            for stamp in general_stamps:
                stamps['general'].append(to_stamp_object(stamp, self.user))
            places_stamps = resources.Tag.objects(tag_type='Locations').order_by("+label")
            for stamp in places_stamps:
                stamps['places'].append(to_stamp_object(stamp, self.user))
            interests_stamps = resources.Tag.objects(tag_type='Social').order_by("+label")
            for stamp in interests_stamps:
                stamps['interests'].append(to_stamp_object(stamp, self.user))
            groups_stamps = resources.Tag.objects(tag_type='Orgs').order_by("+label")
            for stamp in groups_stamps:
                stamps['groups'].append(to_stamp_object(stamp, self.user))
            groups_stamps = resources.Tag.objects(tag_type='Locations').order_by("+label")
            for stamp in groups_stamps:
                stamps['locations'].append(to_stamp_object(stamp, self.user))
            groups_stamps = resources.Tag.objects().order_by("-numUsers")[0:16]
            for stamp in groups_stamps:
                stamps['top'].append(to_stamp_object(stamp, self.user))
            academics_stamps = resources.Tag.objects(category='academics').order_by('+label')
            for stamp in academics_stamps:
                stamps['academics'].append(to_stamp_object(stamp, self.user))
            if postable != 'true':
                people_stamps = resources.Tag.objects(tag_type='user').order_by("-numUsers")
                for stamp in people_stamps:
                    if '@' not in stamp.label:
                        stamps['people'].append(to_stamp_object(stamp, self.user))
            return stamps
        if query:
            search_stamps = resources.Tag.objects(Q(label__icontains=query)).order_by("-numUsers")
            while len(search_stamps) == 0:
                query = query[0:-1]
                search_stamps = resources.Tag.objects(Q(label__icontains=query)).order_by("-numUsers")
            return json.dumps([to_stamp_object(stamp, self.user) for stamp in search_stamps])
        return [to_stamp_object(stamp) for stamp in resources.Tag.objects(tag_permission=0).order_by("+label")]
        
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
            page = self.qs_dict['page'][0]
            order = self.qs_dict['order'][0] if 'order' in self.qs_dict else 'ranking'
            
            messages = resources.Message.objects(Q(tags=stamp) & Q(to_delete__ne=1)).order_by("-" + order)[10*(int(page)-1):10*(int(page)-1)+10]
            return {"stamp":to_stamp_object(stamp),"stamp_photos":resp_photos,"messages_array":[to_message_object(message) for message in messages]}
        return {"stamp":to_stamp_object(stamp),"stamp_photos":resp_photos}
    
    def create(self):
        data = json.loads(self.request.body)
        if 'label' in data and 'description' in data:
            stamp = resources.Tag()
            stamp.location = [34.420830000000002, -119.69819000000001]
            stamp.label = data['label']
            stamp.toolTip = data['description']
            stamp.tag_type = data['catagory']
            stamp.tag_permission = 0
            stamp.save()
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
        elif 'notifications_count' in self.qs_dict:
            return {'notifications_count':self.user.notifications_count}
        return {
                'email':self.user.email,
                'location':self.user.location,
                'username':self.user.personal_tag.label,
                'stamp_image':self.user.personal_tag.stamp_image,
                'stamp_description':self.user.personal_tag.toolTip,
                'uped':[str(message.id) for message in self.user.uped_messages],
                'downed':[str(message.id) for message in self.user.downed_messages],
                'boxed':[str(message.id) for message in self.user.boxed_messages],
                'notifications_count':self.user.notifications_count
            }
            
    def update(self, id):
        data = json.loads(self.request.body)
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
        return {'info':"see status"}
        
def controller_dispatcher(request):
    return eval(request.urlvars['controller']+'(request)')()

def app(environ, start_response):
    req = webob.Request(environ)
    if 'controller' in req.urlvars:
        res = controller_dispatcher(req)
        return res(environ, start_response)
    return webob.Response(body="Hmmm, error?")(environ, start_response)

application = routes.middleware.RoutesMiddleware(app, map)

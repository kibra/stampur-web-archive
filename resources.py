from mongoengine import *
from mongoengine import connection
import datetime

meconnection = connect('soapboxdb')

class StampFeatures:
    EXTERNAL_FEED=1

class Root(object):
    def __init__(self, request):
        self.request = request

class Tag(Document):
    label = StringField(required=True, unique=True)
    tag_type = StringField()
    toolTip = StringField(default='no description')
    photos = ListField(StringField())
    tag_permission = IntField(required=True)
    numUsers = IntField(default=0)
    location = GeoPointField()
    category = StringField(required=True, default='general')
    stamp_image = StringField()
    features = ListField(IntField())
    external_url = StringField()

class StampCollection(Document):
    stamps = ListField(ReferenceField('Tag'))
    owner = ReferenceField('User')
    public = BooleanField(default=False)
    name = StringField(required=True)

class Comment(Document):
    body = StringField(required=True)
    author = ReferenceField('User')
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    ups = IntField(default=0)
    downs = IntField(default=0)
    spams = IntField(default=0)
    ranking = FloatField(default=0)
    anonymous = BooleanField(default=False)
    private = BooleanField(default=False)
    comments = ListField(ReferenceField('Comment'))
    parent_comment = ReferenceField('Comment')
    parent_message = ReferenceField('Message')

class Reply(EmbeddedDocument):
    id = ObjectIdField(required=True, unique=True)
    body = StringField(required=True)
    author = ReferenceField('User')
    name = StringField(max_length=120)
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    ups = IntField(default=0)
    downs = IntField(default=0)
    spams = IntField(default=0)
    ranking = FloatField(default=0)
    anonymous = BooleanField(default=False)
    replies = ListField(EmbeddedDocumentField('Reply'))

class SearchTerm(EmbeddedDocument):
    term = StringField()
    weight = FloatField()

class Message(Document):
    subject = StringField(required=True)
    body = StringField(required=True)
    tags = ListField(ReferenceField('Tag'))
    author = ReferenceField('User')
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    event_date = DateTimeField()
    event_has_time = BooleanField()
    event_location = StringField()
    ups = IntField(default=0)
    downs = IntField(default=0)
    boxeds = IntField(default=0)
    spams = IntField(default=0)
    exclusivity = FloatField(default=0)
    num_replies = IntField(default=0)
    age_range_start = IntField()
    age_range_end = IntField()
    to_males = BooleanField(default=False)
    to_females = BooleanField(default=False)
    latRange = ListField(FloatField())
    lngRange = ListField(FloatField())
    location = GeoPointField()
    radius = FloatField()
    ranking = FloatField(default=0)
    replies = ListField(EmbeddedDocumentField(Reply))
    terms = ListField(EmbeddedDocumentField(SearchTerm))
    filter_type = StringField()
    photos = ListField(StringField())
    to_delete = IntField(default=0)
    comments = ListField(ReferenceField('Comment'))
    private_comments = ListField(ReferenceField('Comment'))
    meta = {
        'indexes': ['ranking']
    }

class Notification(EmbeddedDocument):
    message = ReferenceField('Message')
    comment = ReferenceField('Comment')
    notification_count = IntField(default=0)
    
class CommentNotification(EmbeddedDocument):
    comment = ReferenceField('Comment')
    notification_count = IntField(default=0)

class User(Document):
    email = StringField(required=True, unique=True)
    username = StringField()
    password = StringField(required=True)
    sex = StringField()
    dob = DateTimeField()
    personal_tag = ReferenceField('Tag')
    first_name = StringField()
    last_name = StringField()
    salt = StringField(required=True)
    tag_bucket = ListField(ReferenceField('Tag'))
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    location = GeoPointField()
    comments = ListField(ReferenceField('Comment'))
    notifications_count = IntField(default=0)
    comment_notifications = ListField(EmbeddedDocumentField(CommentNotification))
    sent_messages = ListField(EmbeddedDocumentField(Notification))
    boxed_messages = ListField(ReferenceField('Message'))
    spamed_messages = ListField(ReferenceField('Message'))
    uped_messages = ListField(ReferenceField('Message'))
    downed_messages = ListField(ReferenceField('Message'))
    collections = ListField(ReferenceField('StampCollection'))

class UnconfirmedUser(Document):
    email = StringField()
    email_uc = StringField()
    username = StringField()
    password = StringField(required=True)
    sex = StringField()
    dob = DateTimeField()
    first_name = StringField()
    last_name = StringField()
    salt = StringField(required=True)
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    location = GeoPointField()

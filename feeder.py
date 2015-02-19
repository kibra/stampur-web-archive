import feedparser
import json
import resources
import urllib2
import uuid

from mongoengine import Q
from datetime import datetime
from time import mktime

IMAGEPATH  = '/srv/www/media/feed_images/'

class InvalidLinkException(Exception):
	def __init__(self, message=None, lineNumber=None):
		self.message = message
		self.lineNumber = lineNumber
	def __str__(self):
		return ("Invalid XML: " + message + "line: " + lineNumber)

def verifyFeed(url):
	f = feedparser.parse(url)
	#if f.bozo: 
		#raise InvalidLinkException()
	if not f.entries:
		raise InvalidLinkException()
	if f.feed.has_key('title'):
		title = f.feed.title
	else: title = ''
	if f.feed.has_key('description'):
		description = f.feed.description
	else: description = ''
	#if f.feed.has_key('image'):
		#imageUrl = f.feed.image.href
		#opener = urllib2.build_opener()
		#page = opener.open(imageUrl)
		#image = page.read()
		#imageFilename = IMAGEPATH + str(uuid.uuid4()) + '.' + imageUrl.rsplit('.', 1)[1]
		#print imageFilename
		#fout = open(imageFilename, "wb")
		#fout.write(image)
		#fout.close()		
	#else: imageFilename = ''
	imageFilename = ''
	return dict(title=title, description=description, image=imageFilename)

def updateFeed(stamp):
	fp = feedparser.parse(stamp.external_url)
	print stamp.external_url
	for i in range(0, 1):
		mess = resources.Message()
		mess.subject = fp.entries[i].title
		mess.body = fp.entries[i].summary
		mess.tags = [stamp]
		mess.save()
		print mess.id

#def writeEntriesToJSON():
	#f = open('entries.txt', 'w')
	#for entry in fp.entries:
		#dt = datetime.fromtimestamp(mktime(entry.updated_parsed))
		#entry.updated_parsed = None
		#entry['time_updated'] = dt.isoformat()
	#f.write(repr(entry))
	#f.close()

#def writeAllToJSON():
	#f = open('output.txt', 'w')
	#fp.updated_parsed = None
	#for entry in fp.entries:
		#entry.updated_parsed = None
	#f.write(repr(fp))
	#f.close()

stamps = resources.Tag.objects(features=resources.StampFeatures.EXTERNAL_FEED)
for s in stamps:
	fp = feedparser.parse(s.external_url)
	if not f.entries:
		print str(s.id) + ' (' + str(s.label) + ')\t' + 'FAIL' 
	else:
		updateFeed(s)
		print str(s.id) + ' (' + str(s.label) + ')\t' + 'updated' 



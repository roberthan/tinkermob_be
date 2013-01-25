from django.contrib.auth.models import User
from django.db import models
from tastypie.models import create_api_key
from django.db.models.signals import pre_save, post_save
from django.db.models import F
from datetime import datetime, timedelta
import time
post_save.connect(create_api_key, sender=User)
from imagekit.models import ImageSpecField
from imagekit.processors import ResizeToFill, Adjust
from django.template.defaultfilters import slugify
import hashlib

def getUID(user):
    return str(user.id)+'-'+str(int(round(time.time() * 1000)))

def getRevisionID():
    return int(round(time.time()))

import uuid, os
def get_file_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('uploaded_img', filename)

#filters out all private and deleted entries
class ActiveManager(models.Manager):
    def get_query_set(self):
        return super(ActiveManager, self).get_query_set().exclude(is_active=False)

class TempAuthManager(models.Manager):
    def createTempAuth(self, user):
        temp_auth = self.create(user=user)
        temp_auth.save()
        return temp_auth

class TempAuth(models.Model):
    user  = models.ForeignKey(User)
    expiration_date = models.DateTimeField(default=(datetime.now()+timedelta(days=14)))
    hash_key = models.CharField(max_length=40, blank=True)
    objects = TempAuthManager()
    def __unicode__(self):
        return self.hash_key
def TempAuth_pre_save(sender, instance, **kwargs):
    if not instance.hash_key:
        hash = hashlib.sha1()
        hash.update(str(time.time())+instance.user.username)
        instance.hash_key = hash.hexdigest()[:40]
pre_save.connect(TempAuth_pre_save, sender=TempAuth)

class Image(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    user  = models.ForeignKey(User)
    original_image = models.ImageField(upload_to=get_file_path, blank=True, null=True)
#    original_image = models.ImageField(upload_to='uploaded_img', blank=True, null=True)
    formatted_image = ImageSpecField(image_field='original_image', format='JPEG'
            ,options={'quality': 90})
    tile_image = ImageSpecField([ResizeToFill(290, 228, False)], image_field='original_image',format='JPEG')
    icon_image = ImageSpecField([ResizeToFill(64, 64, False)], image_field='original_image',format='JPEG')
        #, options={'quality': 90})
#    profile_image = ImageSpec([resize.Fit(160, 120, False)], image_field='original_image',
#        format='JPEG')#, options={'quality': 90})
#    thumbnail = ImageSpec([Adjust(contrast=1.2, sharpness=1.1),
#                           resize.Crop(80, 80)], image_field='original_image',
#        format='JPEG')#, options={'quality': 90})
#    landing_thumbnail = ImageSpec([Adjust(contrast=1.2, sharpness=1.1),
#                                   resize.Crop(125, 90)], image_field='original_image',
#        format='JPEG')#, options={'quality': 90})
    filename = models.CharField(max_length=255, blank=True)
    num_views = models.PositiveIntegerField(editable=False, default=0)
    text = models.TextField (blank=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    revision = models.IntegerField(editable=False)
def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.save()
    #    class IKOptions:
    #        # This inner class is where we define the ImageKit options for the model
    #        spec_module = 'badideas.base.specs'
    #        cache_dir = 'photos'
    #        image_field = 'original_image'
    #        save_count_as = 'num_views'

def image_pre_save(sender, instance, **kwargs):
    if not instance.id:
        instance.id=getUID(instance.user)
    instance.revision = getRevisionID()
pre_save.connect(image_pre_save, sender=Image)

class Location(models.Model):
    name = models.CharField(max_length=255, blank=True)
    lat = models.CharField(max_length=75, blank=True)
    lon = models.CharField(max_length=75, blank=True)
    user  = models.ForeignKey(User)
    text = models.TextField(blank=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True, editable=False)
    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
    def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.save()

# sample fb user profile from passport
#    {"provider":"facebook","id":"1036290190","username":"robert.han","displayName":"Robert Han","name":{"familyName":"Han","givenName":"Robert"},"gender":"male","profileUrl":"http://www.facebook.com/robert.han","emails":[{"value":"roberthan818@gmail.com"}],"_raw":"{\"id\":\"1036290190\",\"name\":\"Robert Han\",\"first_name\":\"Robert\",\"last_name\":\"Han\",\"link\":\"http:\\/\\/www.facebook.com\\/robert.han\",\"username\":\"robert.han\",\"hometown\":{\"id\":\"113216112023878\",\"name\":\"Culver City, California\"},\"location\":{\"id\":\"108056275889020\",\"name\":\"Cambridge, Massachusetts\"},\"gender\":\"male\",\"email\":\"roberthan818\\u0040gmail.com\",\"timezone\":-7,\"locale\":\"en_US\",\"verified\":true,\"updated_time\":\"2012-06-07T18:56:56+0000\"}","_json":{"id":"1036290190","name":"Robert Han","first_name":"Robert","last_name":"Han","link":"http://www.facebook.com/robert.han","username":"robert.han","hometown":{"id":"113216112023878","name":"Culver City, California"},"location":{"id":"108056275889020","name":"Cambridge, Massachusetts"},"gender":"male","email":"roberthan818@gmail.com","timezone":-7,"locale":"en_US","verified":true,"updated_time":"2012-06-07T18:56:56+0000"}
class SocialAuth(models.Model):
    provider = models.CharField (max_length=255)
    provider_id = models.CharField (max_length=255)
    username = models.CharField (max_length=255, blank=True)
    display_name = models.CharField (blank=True,max_length=255)
    email = models.CharField (max_length=255)
    profile_url = models.CharField (blank=True,max_length=255)
    user = models.ForeignKey(User)
    _json = models.TextField(blank=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True, editable=False)
    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
    def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.save()

PUSH_LEVEL = (
    (u'0', u'nothing'),
    (u'1', u'ideas'),
    (u'2', u'ideas_snapshots'),
    )

NOTIFY_LEVEL = (
    (u'0', u'never'),
    (u'1', u'ideas')
    )

class Profile(models.Model):
    user = models.OneToOneField(User, primary_key=True,)
    location = models.ForeignKey(Location, blank=True, null=True)
    profile_image = models.ForeignKey(Image, blank=True, null=True)
    display_name = models.CharField (max_length=255, blank= True)
    location_text = models.CharField (max_length=255, blank= True)
    bio = models.TextField(blank=True)
    website = models.CharField(blank=True, max_length=255)
    fb_push = models.CharField (max_length=1, choices=PUSH_LEVEL, default='1' )
    twitter_push = models.CharField (max_length=1, choices=PUSH_LEVEL, default='1' )
    newsletter_setting = models.BooleanField(default=True)
    notify_setting = models.CharField (max_length=1, choices=NOTIFY_LEVEL, default='1' )
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    revision = models.IntegerField(editable=False)
    supporters = models.ManyToManyField('self', through='supportUser', symmetrical=False, blank=True, null=True)

def profile_pre_save(sender, instance, **kwargs):
    instance.revision = getRevisionID()
pre_save.connect(profile_pre_save, sender=Profile)
#Ideas
class Idea(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    tag_line = models.CharField (max_length=140)
    user = models.ForeignKey(User)
    text = models.TextField(blank=True)
#    profile_image = models.ForeignKey(Image, blank=True, null=True)
    image = models.ForeignKey(Image, blank=True, null=True)
    location = models.ForeignKey(Location, blank=True, null=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True, editable=False)
    revision = models.IntegerField(editable=False)
    supporters = models.ManyToManyField(User, through='supportIdea', blank=True, null=True, related_name='idea_supported' )
    horizontal_size = models.IntegerField(default=1)
    vertical_size = models.IntegerField(default=1)
    ordering = models.PositiveIntegerField(editable=False, default=-1)

    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
    def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.ordering=None
        self.save()
    def update_order(self,new_ordering):
        if self.ordering < 0:
            qs = Idea.actives.filter(user=self.user).order_by('-ordering')
            try:
                self.ordering = qs[0].ordering + 1
            except IndexError:
                self.ordering = 0
        diff = new_ordering - self.ordering
        if diff < 0:
            Idea.objects.filter(user=self.user).filter(ordering__gt=(new_ordering-1)).filter(ordering__lt=self.ordering).update(ordering=F('ordering') + 1)
            self.ordering=new_ordering
            self.save()
        elif diff > 0:
            Idea.objects.filter(user=self.user).filter(ordering__lt=(new_ordering+1)).filter(ordering__gt=self.ordering).update(ordering=F('ordering') - 1)
            self.ordering=new_ordering
            self.save()

def idea_pre_save(sender, instance, **kwargs):
    if not instance.id:
        instance.id=getUID(instance.user)
    instance.revision = getRevisionID()
    if instance.ordering < 0:
        qs = Idea.actives.filter(user=instance.user).order_by('-ordering')
        try:
            instance.ordering = qs[0].ordering + 1
        except IndexError:
            instance.ordering = 0
    temp_list=instance.tag_line.split()
    hashtags_text=[]
    for term in temp_list:
        if term.partition('#')[2]:
            text = slugify(term.lower().strip().partition('#')[2])
            hashtags_text.append(text)
            try:
                hashtag=Hashtag.objects.filter(text=text).latest('pk')
            except Hashtag.DoesNotExist:
                hashtag=Hashtag(text=text)
                hashtag.save()
            hashtag.ideas.add(instance)
    #remove old hashtags
    for item in instance.hashtag_set.all():
        if item.text not in hashtags_text:
            instance.hashtag_set.remove(item)
pre_save.connect(idea_pre_save, sender=Idea)

class reservedUsername(models.Model):
    username = models.CharField(max_length=30)
    def __unicode__(self):
        return self.text
    class Meta:
        ordering = ('username',)

class Hashtag(models.Model):
    text = models.CharField(max_length=140)
    ideas = models.ManyToManyField(Idea,  blank=True, null=True, editable=False)
    def __unicode__(self):
        return self.text
    class Meta:
        ordering = ('text',)
#Snapshots
class Snapshot(models.Model):
    id = models.CharField(max_length=255, primary_key=True, blank=True)
    idea = models.ForeignKey(Idea)
    user = models.ForeignKey(User)
    text = models.TextField(blank=True)
    image = models.ForeignKey(Image, blank=True, null=True)
    location = models.ForeignKey(Location, blank=True, null=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    revision = models.IntegerField(editable=False)
    is_active=models.BooleanField(default=True, editable=False)
    horizontal_size = models.IntegerField(default=1)
    vertical_size = models.IntegerField(default=1)
    ordering = models.PositiveIntegerField(editable=False, default=-1)

    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
    def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.ordering=None;
        self.save()
    def update_order(self,new_ordering):
        if self.ordering < 0:
            qs = Snapshot.actives.filter(idea=self.idea).order_by('-ordering')
            try:
                self.ordering = qs[0].ordering + 1
            except IndexError:
                self.ordering = 0
        diff = new_ordering-self.ordering
        if diff < 0:
            Snapshot.objects.filter(idea=self.idea).filter(ordering__gt=(new_ordering-1)).filter(ordering__lt=self.ordering).update(ordering=F('ordering') + 1)
            self.ordering=new_ordering
            self.save()
        elif diff > 0:
            Snapshot.objects.filter(idea=self.idea).filter(ordering__lt=(new_ordering+1)).filter(ordering__gt=self.ordering).update(ordering=F('ordering') - 1)
            self.ordering=new_ordering
            self.save()

def snapshot_pre_save(sender, instance, **kwargs):
#    print instance.ordering
    if not instance.id:
        instance.id=getUID(instance.user)
    instance.revision = getRevisionID()
    print 'new revision'
    if instance.ordering < 0:
        qs = Snapshot.actives.filter(idea=instance.idea).order_by('-ordering')
        try:
            instance.ordering = qs[0].ordering + 1
        except IndexError:
            instance.ordering = 0
pre_save.connect(snapshot_pre_save, sender=Snapshot)

#Questions
class Question(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    idea = models.ForeignKey(Idea)
    user = models.ForeignKey(User)
    text = models.TextField(blank=True)
    snapshot = models.ForeignKey(Snapshot, blank=True, null=True)
    location = models.ForeignKey(Location, blank=True, null=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    revision = models.IntegerField(editable=False)
    is_active=models.BooleanField(default=True, editable=False)
    supporters = models.ManyToManyField(User, through='supportQuestion', blank=True, null=True, related_name='questions_rated')

    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
    def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.save()
def question_pre_save(sender, instance, **kwargs):
    if not instance.id:
        instance.id=getUID(instance.user)
    instance.revision = getRevisionID()
pre_save.connect(question_pre_save, sender=Question)

#Answers
class Answer(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    idea = models.ForeignKey(Idea)
    user = models.ForeignKey(User)
    question = models.ForeignKey(Question)
    text = models.TextField(blank=True)
    location = models.ForeignKey(Location, blank=True, null=True)
    created_on = models.DateTimeField(default=datetime.now)
    modified_on = models.DateTimeField(default=datetime.now)
    revision = models.IntegerField(editable=False)
    is_active=models.BooleanField(default=True, editable=False)
    supporters = models.ManyToManyField(User, through='supportAnswer', blank=True, null=True, related_name='answers_rated')

    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
    def delete(self, *args, **kwargs):
        self.modified_on = datetime.now
        self.is_active = False
        self.save()
def answer_pre_save(sender, instance, **kwargs):
    if not instance.id:
        instance.id=getUID(instance.user)
    instance.revision = getRevisionID()
pre_save.connect(answer_pre_save, sender=Answer)

#Support: Idea
class supportIdea(models.Model):
    idea = models.ForeignKey(Idea)
    supporter = models.ForeignKey(User)
    created_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True)

    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
#    def __unicode__(self):
#        return self.supporter.username

#Support: User
class supportUser(models.Model):
    user = models.ForeignKey(Profile, related_name = 'source')
    supporter = models.ForeignKey(Profile, related_name = 'target')
    created_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True)
    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()
#Support Question/Answer
class supportQuestion(models.Model):
    question = models.ForeignKey(Question)
    supporter = models.ForeignKey(User)
    up_rank = models.IntegerField(default=1)
    created_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True)
    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()

#Support Question/Answer
class supportAnswer(models.Model):
    answer = models.ForeignKey(Answer)
    supporter = models.ForeignKey(User)
    up_rank = models.IntegerField(default=1)
    created_on = models.DateTimeField(default=datetime.now)
    is_active=models.BooleanField(default=True)
    # The default model manager
    objects = models.Manager()
    # public manager
    actives = ActiveManager()

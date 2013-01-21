from tastypie.authentication import ApiKeyAuthentication, BasicAuthentication
from tastypie.authorization import DjangoAuthorization, Authorization
from tastypie.resources import ModelResource
from tastypie import fields
from tastypie.cache import SimpleCache
from tastypie.models import ApiKey
from tastypie.exceptions import BadRequest
from tastypie.api import Api
from tastypie.exceptions import ImmediateHttpResponse
from tastypie.http import HttpNotModified, HttpForbidden
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from models import *
from django.contrib.auth.models import User, AnonymousUser
from django.core.validators import email_re
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.conf.urls.defaults import url
from django.db.models import Count, Sum
from django.template.defaultfilters import slugify
from django.db.models import Q
from random import choice
from string import letters
from datetime import datetime
from time import mktime


def is_valid_email(email):
    return True if email_re.match(email) else False

class BackboneCompatibleResource(ModelResource):
    class Meta:
        always_return_data = True
#    def alter_list_data_to_serialize(self, request, data):
#        return data["objects"]

def preHydrate(bundle):
    if bundle.data.has_key('resource_uri'):
        del bundle.data['resource_uri']
    if bundle.data.has_key('user'):
        del bundle.data['user']
    return bundle

class AnonymousApiKeyAuthentication(ApiKeyAuthentication):
    def is_authenticated(self, request, **kwargs):
        # Run the super method, but don't return what we get back.
        # This will populate ``request.user`` is they're auth'd.
#        result = super(ApiKeyAuthentication,self).is_authenticated(request, **kwargs)
        if request.GET.__contains__('userid'):
            request_get=request.GET.copy()
            user_id = request_get.get('userid')
            try:
                username = User.objects.get(id = user_id).username
            except ObjectDoesNotExist:
                return self._unauthorized()
#            username = 'ubuntu'
            request_get.__setitem__('username',username)
            request.GET = request_get
        result = super(AnonymousApiKeyAuthentication,self).is_authenticated(request, **kwargs)
        if result is True:
            return True
        if request.user and not request.user.is_anonymous():
            # We found credentials but they were wrong.
            return self._unauthorized()
        #            raise ImmediateHttpResponse(
        #                HttpForbidden("Invalid Auth")
        #            )
        else:
            # They're not auth'd. If it's a GET, let them through.
            # Otherwise, deny.
            if request.method != 'GET':
                return self._unauthorized()
            else:
                request.user = AnonymousUser()
        return True

class AnonymousPostApiKeyAuthentication(ApiKeyAuthentication):
    def is_authenticated(self, request, **kwargs):
        # Run the super method, but don't return what we get back.
        # This will populate ``request.user`` is they're auth'd.
#        result = super(ApiKeyAuthentication,self).is_authenticated(request, **kwargs)
        if request.GET.__contains__('userid'):
            request_get=request.GET.copy()
            user_id = request_get.get('userid')
            try:
                username = User.objects.get(id = user_id).username
            except ObjectDoesNotExist:
                return self._unauthorized()
#            username = 'ubuntu'
            request_get.__setitem__('username',username)
            request.GET = request_get
        result = super(AnonymousPostApiKeyAuthentication,self).is_authenticated(request, **kwargs)
        if result is True:
            return True
        if request.user and not request.user.is_anonymous():
            # We found credentials but they were wrong.
            return self._unauthorized()
        #            raise ImmediateHttpResponse(
        #                HttpForbidden("Invalid Auth")
        #            )
        else:
            request.user = AnonymousUser()
        return True

def convertDate(date):
    time = mktime(date.timetuple())
    time +=  (date.microsecond / 1000000.0)
    return round(time * 1000)

#class VerifyResource(BackboneCompatibleResource):
#    class Meta:
#        queryset = User.objects.all()
#        resource_name = 'verify'
#        fields = ['email']
#        allowed_methods = ['get']
#        authentication = BasicAuthentication()
#
#    def alter_list_data_to_serialize(self, request, data):
#        return data["objects"]
#
#    def dehydrate(self, bundle):
#        u=bundle.request.user
#        bundle.data['apiKey'] = ApiKey.objects.get(user=u)
#        return bundle
#
#    def apply_authorization_limits(self, request, object_list):
#        return object_list.filter(id=request.user.id)

class ProfileResource(ModelResource):
    class Meta:
        queryset = Profile.objects.all()
        resource_name = 'profile'
        include_resource_uri = False
        include_absolute_url = False
        allowed_methods = []

class UserResource(BackboneCompatibleResource):
    #    supporter = fields.ForeignKey(UserResource, 'user')
#    profile = fields.ToOneField(ProfileResource, 'get_profile', full=True)
    class Meta:
        queryset = User.objects.all()
        resource_name = 'user'
        fields = ['id','modified_on']
#        excludes = ['username']
        #        allowed_methods = ['get']
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        filtering = {
#            "user": ('exact')
            "id": ('exact')
        }
        ordering = [
            'modified_on',
            ]
        always_return_data = True

    def override_urls(self):
        return [
            url(r"^(?P<resource_name>%s)/(?P<username>[\w\d_.-]+)/$" % self._meta.resource_name, self.wrap_view('dispatch_detail'), name="api_dispatch_detail"),
            ]

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        if bundle.data.has_key('resource_uri'):
            del bundle.data['resource_uri']
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
            #convert javascript timestamp to python datetime
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.data.has_key('modified_on'):
            if isinstance(bundle.data['modified_on'], (int, long)):
                #convert javascript timestamp to python datetime
                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
        if bundle.request.method == 'PUT' or bundle.request.method == 'PATCH':
            try:
                user = User.objects.get(id=bundle.request.user.id)
                bundle.obj = user
            except ObjectDoesNotExist:
                raise BadRequest('not authorized')
            try:
                profile = Profile.objects.get(user = bundle.obj)
            except Profile.DoesNotExist:
                profile = Profile(user = bundle.obj)
            if bundle.data.has_key('image'):
                image_id=bundle.data['image']
                try:
                    image = Image.objects.get(id=image_id)
                    if image.user != bundle.request.user:
                        raise BadRequest('image not authorized')
                    else:
                        profile.profile_image=image
                except ObjectDoesNotExist:
                    image = Image(id=image_id, user = bundle.request.user)
                    image.save()
                    profile.profile_image=image
            if bundle.data.has_key('email'):
                e = bundle.data['email']
                if e != user.email:
                    if not User.objects.filter(email=e).exists():
                        user.email = bundle.data['email']
                    else:
                        raise ImmediateHttpResponse(
                            HttpForbidden("Email in Use")
                        )
            if bundle.data.has_key('username'):
                u = bundle.data['username']
                if not u == user.username:
                    if not User.objects.filter(username=e).exists():
                        user.username = bundle.data['username']
                    else:
                        raise ImmediateHttpResponse(
                            HttpForbidden("Username in Use")
                        )
            if bundle.data.has_key('display_name'):
                profile.display_name = bundle.data['display_name']
            if bundle.data.has_key('password'):
                user.set_password(bundle.data['password'])
                del bundle.data['password']
            if bundle.data.has_key('bio'):
                profile.bio = bundle.data['bio']
            if bundle.data.has_key('location_text'):
                profile.location_text = bundle.data['location_text']
            if bundle.data.has_key('website'):
                profile.website = bundle.data['website']
            if bundle.data.has_key('fb_push'):
                profile.fb_push = bundle.data['fb_push']
            if bundle.data.has_key('twitter_push'):
                profile.twitter_push = bundle.data['twitter_push']
            if bundle.data.has_key('newsletter_setting'):
                profile.newsletter_setting = bundle.data['newsletter_setting']
            if bundle.data.has_key('notify_setting'):
                profile.notify_setting = bundle.data['notify_setting']
            if bundle.data.has_key('facebook_auth'):
                if bundle.data['facebook_auth'] == 0:
                    SocialAuth.actives.filter(user = bundle.obj).filter(provider = 'facebook').all().update(is_active=False)
            if bundle.data.has_key('twitter_auth'):
                if bundle.data['twitter_auth'] == 0:
                    SocialAuth.actives.filter(user = bundle.obj).filter(provider = 'twitter').all().update(is_active=False)
                #            if  bundle.data.has_key('modified_on') and user:
#                if bundle.data['modified_on'] > user.get_profile().modified_on:
#                    bundle.data['user']=bundle.request.user
#                    return bundle
#                else:
#                    raise ImmediateHttpResponse(
#                        HttpNotModified("Request Outdated")
#                    )
            profile.save()
            user.save()
#        raise ImmediateHttpResponse(
#            HttpForbidden("Check ID")
#        )
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['username'] = bundle.obj.username
        try:
            profile = Profile.objects.get(user = bundle.obj)
        except Profile.DoesNotExist:
            profile = Profile(user = bundle.obj )
            profile.save()
#        bundle.data['modified_on'] = convertDate(bundle.obj.profile.modified_on)
        idea = Idea.actives.filter(user=bundle.obj)
        idea_values = idea.values_list('id', flat=True).order_by('-modified_on')[:5]
        temp = []
        for i in idea_values:
            temp.append(i)
        bundle.data['ideas'] = temp
        if bundle.request.user and not bundle.request.user.is_anonymous():
            if supportUser.actives.filter(supporter=bundle.request.user.get_profile()).filter(user=bundle.obj).exists():
                bundle.data['is_following']=True
            else:
                bundle.data['is_following']=False
        bundle.data['count_ideas'] = idea.count()
        bundle.data['display_name'] = bundle.obj.profile.display_name
        bundle.data['bio'] = bundle.obj.profile.bio
        bundle.data['website'] = bundle.obj.profile.website
        bundle.data['location_text'] = bundle.obj.profile.location_text
        bundle.data['joined_on'] = bundle.obj.profile.created_on
        bundle.data['revision'] = bundle.obj.profile.revision
        if bundle.obj.profile.profile_image:
            if bundle.obj.profile.profile_image.original_image:
                bundle.data['profile_image'] = bundle.obj.profile.profile_image.original_image.url
                bundle.data['tile_image'] = bundle.obj.profile.profile_image.tile_image.url
                bundle.data['icon_image'] = bundle.obj.profile.profile_image.icon_image.url
        following = supportUser.actives.filter(supporter=bundle.obj)
#        following_values=following.values_list('user', flat=True).order_by('-pk')[:5]
#        temp = []
#        for i in following_values:
#            temp.append(i)
        bundle.data['count_followings'] = following.count()
        follower = supportUser.actives.filter(user=bundle.obj)
#        follower_values=follower.values_list('supporter', flat=True).order_by('-pk')[:5]
#        temp = []
#        for i in follower_values:
#            temp.append(i)
#        bundle.data['followers'] = temp
        bundle.data['count_followers'] = follower.count()
        support_ideas = supportIdea.actives.filter(supporter=bundle.obj)
        bundle.data['count_support_ideas'] = support_ideas.count()
        if not bundle.request.user.is_anonymous():
            if bundle.request.user.pk == bundle.obj.pk:
                bundle.data['email'] = bundle.obj.email
                bundle.data['fb_push'] = bundle.obj.profile.fb_push
                bundle.data['twitter_push'] = bundle.obj.profile.twitter_push
                bundle.data['newsletter_setting'] = bundle.obj.profile.newsletter_setting
                bundle.data['notify_setting'] = bundle.obj.profile.notify_setting
                s_auth = SocialAuth.actives.filter(user = bundle.obj).all()
                for auth in s_auth:
                    bundle.data[auth.provider+'_auth']=auth.username
#            bundle.data['snapshots'] = Snapshot.actives.filter(idea__user=bundle.obj).values_list('id', flat=True).order_by('-ordering')
#            bundle.data['supporters'] = supportIdea.objects.filter(user=bundle.obj).values_list('id', flat=True).order_by('-pk')
            #            del(bundle.data['email'])
        return bundle

class SocialAuthResource(BackboneCompatibleResource):
    class Meta:
        queryset = SocialAuth.actives.all()
        resource_name = 'social'
        fields = ['provider','provider_id','username','display_name','email','_json','created_on','profile_url','modified_on']
        authorization = Authorization()
        authentication = AnonymousPostApiKeyAuthentication()
        allowed_methods = ['post']
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        if bundle.data.has_key('resource_uri'):
            del bundle.data['resource_uri']
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
            #convert javascript timestamp to python datetime
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.data.has_key('modified_on'):
            if isinstance(bundle.data['modified_on'], (int, long)):
                #convert javascript timestamp to python datetime
                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
        if not bundle.data.has_key('provider') or not bundle.data.has_key('id'):
            raise BadRequest('provider missing')
#        if len(bundle.data['emails']) < 1:
#            raise BadRequest('no emails')
        bundle.data['provider_id']=bundle.data['id']
        del bundle.data['id']
        bundle.data['display_name']=bundle.data['displayName']
        del bundle.data['displayName']
        if bundle.data.has_key('profileUrl'):
            bundle.data['profile_url']=bundle.data['profileUrl']
            del bundle.data['profileUrl']
        if bundle.data.has_key('emails'):
            bundle.data['email']=(bundle.data['emails'][0])['value']
            del bundle.data['emails']
        try:
            s_all = SocialAuth.actives.filter(provider=bundle.data['provider'])
            s = s_all.get(provider_id=bundle.data['provider_id'])
        except ObjectDoesNotExist:
            #create new
            s = SocialAuth()
            if not bundle.request.user.is_anonymous():
                s.user = bundle.request.user
                bundle.obj = s
                s_all.filter(user =bundle.request.user).all().update(is_active = False)
                return bundle
            elif bundle.data.has_key('email'):
                email = bundle.data['email']
                password = ''.join([choice(letters) for i in xrange(30)])
                username = ''
                if is_valid_email(email) and User.objects.filter(email=email).count() == 0:
                    username = email.strip().lower().partition('@')[0][:30]
                else:
                    raise BadRequest('email already in use, please log in')
                if User.objects.filter(username__exact=username).exists() or reservedUsername.objects.filter(username__exact=username).exists():
                    username = ''.join([choice(letters) for i in xrange(30)])
                try:
                    user = User.objects.create_user(username, email, password)
                    profile = Profile.objects.create(user = user)
                except BaseException:
                    raise BadRequest('duplicates user error')
                s.user = user
                bundle.obj = s
                return bundle
        except MultipleObjectsReturned:
            raise BadRequest('duplicates returned error')
        #user is logged in, check if the email is already in use, if not then add it
        if not bundle.request.user.is_anonymous() and bundle.request.user.id != s.user.id:
            raise BadRequest('social profile already in use')
#       disable old social profiles
        if not bundle.request.user.is_anonymous():
            old_socials = SocialAuth.actives.filter(provider=bundle.data['provider']).filter(user=bundle.request.user).exclude(provider_id=bundle.data['provider_id']).update(is_active=False)
            bundle.request.user = s.user
        bundle.obj = s
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['user']=bundle.obj.user.id
        bundle.data['username']=bundle.obj.user.username
        bundle.data['api_key'] = ApiKey.objects.get(user=bundle.obj.user).key
        bundle.data['auth_key'] = TempAuth.objects.createTempAuth(bundle.obj.user)
        #
#            bundle.data['snapshots'] = Snapshot.actives.filter(idea__user=bundle.obj).values_list('id', flat=True).order_by('-ordering')
#            bundle.data['supporters'] = supportIdea.objects.filter(user=bundle.obj).values_list('id', flat=True).order_by('-pk')
            #            del(bundle.data['email'])
        return bundle

class ImageResource(BackboneCompatibleResource):
    class Meta:
        queryset = Image.objects.all()
        resource_name = 'image'
#        fields = ['first_name', 'last_name', 'id']
        #        excludes = ['username']
        allowed_methods = []
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        filtering = {
        }

#    def obj_create(self, bundle, request=None, **kwargs):
#        email, password = bundle.data['email'], bundle.data['password']
#        username = ''
#        if is_valid_email(email) and User.objects.filter(email=email).count() == 0:
#            username = email.partition('@')[0][:30]
#            count = User.objects.filter(username=username).count()
#            if count >= 1:
#                username = ''.join([choice(letters) for i in xrange(30)])
#        try:
#            bundle.obj = User.objects.create_user(username, email, password)
#        except BaseException:
#            raise BadRequest('That email already exists:'+username+':'+email)
#        return bundle
#
#    def hydrate(self, bundle):
#        if bundle.data.has_key('created_on'):
#            if isinstance(bundle.data['created_on'], (int, long)):
#            #convert javascript timestamp to python datetime
#                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
#        if bundle.data.has_key('modified_on'):
#            if isinstance(bundle.data['modified_on'], (int, long)):
#                #convert javascript timestamp to python datetime
#                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
#        return bundle
#
#    def dehydrate(self, bundle):
#        return bundle
#
#class ManageSelfResource(BackboneCompatibleResource):
#    class Meta:
#        queryset = User.objects.all()
#        resource_name = 'settings'
#        fields = ['username', 'email', 'last_login']
#        excludes = ['id']
#        authorization = Authorization()
#        authentication = AnonymousApiKeyAuthentication()
#        #        cache = SimpleCache()
#        #        authorization = DjangoAuthorization()
##        authentication = ApiKeyAuthentication()
#        allowed_methods = ['put']

    def hydrate(self, bundle):
        if bundle.data.has_key('new_password'):
            u = bundle.request.user
            u.set_password(bundle.data['new_password'])
            u.save()
            bundle.data['password'] = u.password
        return bundle

class IdeaResource(ModelResource):
    user = fields.ForeignKey(UserResource, 'user')
#    snapshots = fields.ManyToManyField('sleepyswan.core.api.SnapshotResource', 'snapshot_set')
    class Meta:
        queryset = Idea.actives.annotate(supporter_count=Count('supportidea')).order_by('-supporter_count')
        resource_name = 'idea'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['id', 'resource_uri', 'tag_line', 'text','revision','modified_on', 'is_active', 'image']#'horizontal_size', 'vertical_size',
#        excludes = ['is_active']
        allowed_methods = ['get','post','put']
        filtering = {
            "user": ('exact'),
        }
        ordering = [
            'ordering',
            'modified_on',
            ]
        always_return_data = True

    def build_filters(self, filters=None):
        if filters is None: #if you don't pass any filters at all
            filters = {}
        orm_filters = super(IdeaResource, self).build_filters(filters)
#        if 'hashtag' in filters:
#            text = slugify(filters['hashtag'].lower().strip())
#            qs = Idea.actives.filter(hashtag__text=text).all()
#            orm_filters["pk__in"] = [i.pk for i in qs]
        if('hashtag' in filters):
            query = slugify(filters['hashtag'].lower().strip())
            qset = (Q(hashtag__text=query))
            orm_filters.update({'custom': qset})
        elif 'support' in filters:
            text = filters['support']
            qs = supportIdea.actives.filter(supporter__id=text).values_list('idea', flat=True)
            print qs
            orm_filters["pk__in"] = [i for i in qs]
        return orm_filters

    def apply_filters(self, request, applicable_filters):
        if 'custom' in applicable_filters:
            custom = applicable_filters.pop('custom')
        else:
            custom = None
        semi_filtered = super(IdeaResource, self).apply_filters(request, applicable_filters)
        return semi_filtered.filter(custom) if custom else semi_filtered

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        bundle = preHydrate(bundle)
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
            #convert javascript timestamp to python datetime
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.data.has_key('modified_on'):
            if isinstance(bundle.data['modified_on'], (int, long)):
                #convert javascript timestamp to python datetime
                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.request.user:
                bundle.data['user']=bundle.request.user
        elif bundle.request.method == 'PUT' or bundle.request.method == 'PATCH':
            id=''
            if bundle.data.has_key('id') and bundle.data.has_key('revision'):
                id= bundle.data['id']
                revision = bundle.data['revision']
                try:
                    idea = Idea.actives.filter(user=bundle.request.user.id).filter(revision=revision).get(id=id)
                except ObjectDoesNotExist:
                    raise BadRequest('not authorized')
                if bundle.data.has_key('ordering'):
#                        idea.update_order(bundle.data['ordering'])
                    del bundle.data['ordering']
                if bundle.data.has_key('image'):
                    image_id=bundle.data['image']
                    if not idea.image or not idea.image.pk == image_id:
                        try:
                            image = Image.objects.get(id=image_id)
                            if image.user != bundle.request.user:
                                raise BadRequest('image not authorized')
                            else:
                                print 'save'
                                idea.image=image
                                idea.save()
                        except ObjectDoesNotExist:
                            image = Image(id=image_id, user = bundle.request.user)
                            image.save()
                            idea.image=image
                            idea.save()
                    return bundle
            raise ImmediateHttpResponse(
                HttpForbidden("Check ID")
            )
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        user = bundle.obj.user
        bundle.data['user'] =  user.id
        bundle.data['username'] =  user.username
        user_img = user.profile.profile_image
        if user_img:
            bundle.data['user_icon_image'] = user_img.icon_image.url
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        bundle.data['modified_on'] = convertDate(bundle.obj.modified_on)
#        if not bundle.request.user.is_anonymous():
#        bundle.data['snapshots'] = Snapshot.actives.filter(idea=bundle.obj).values_list('id', flat=True).order_by('-ordering')
        snapshot = Snapshot.actives.filter(idea=bundle.obj)
        snapshot_value=snapshot.values_list('id', flat=True).order_by('-ordering')[:5]
        temp = []
        for i in snapshot_value:
            temp.append(i)
        bundle.data['snapshots'] = temp
        bundle.data['count_snapshots'] = snapshot.count()
        support = supportIdea.actives.filter(idea=bundle.obj)
        support_values=support.values_list('supporter__username', flat=True).order_by('-pk')[:5]
        if bundle.request.user and not bundle.request.user.is_anonymous():
            if support.filter(supporter=bundle.request.user).exists():
                bundle.data['is_supporter']=True
            else:
                bundle.data['is_supporter']=False
        temp = []
        for i in support_values:
            temp.append(i)
        bundle.data['supporters'] = temp
        bundle.data['count_supporters'] = support.count()
        question = Question.actives.filter(idea=bundle.obj)
        question_values = question.values_list('id', flat=True).order_by('-pk')[:5]
        temp = []
        for i in question_values:
            temp.append(i)
        bundle.data['questions'] = temp
        bundle.data['count_questions'] = question.count()
        if bundle.obj.image:
            bundle.data['image'] = bundle.obj.image.id
            if bundle.obj.image.tile_image :
                bundle.data['original_image'] = bundle.obj.image.original_image.url
                bundle.data['tile_image'] = bundle.obj.image.tile_image.url
                bundle.data['icon_image'] = bundle.obj.image.icon_image.url
        if not bundle.obj.is_active:
                bundle.data['destroy']= True
        return bundle

class SnapshotResource(ModelResource):
    user = fields.ForeignKey(UserResource, 'user')#, null=True
    idea = fields.ForeignKey(IdeaResource, 'idea')
#    image = fields.ForeignKey(ImageResource, 'image', null=True)

    class Meta:
        queryset = Snapshot.actives.all().order_by('ordering')
        resource_name = 'snapshot'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['id', 'resource_uri', 'text', 'horizontal_size', 'vertical_size', 'ordering','revision', 'modified_on', 'image','is_active']
#        excludes = ['is_active']
        allowed_methods = ['get','post','put']
        filtering = {
            "user": ('exact'),
            "idea": ('exact')
        }
        ordering = [
            'ordering',
            'modified_on',
        ]
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        bundle = preHydrate(bundle)
        #convert javascript timestamp to python datetime
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.data.has_key('modified_on'):
            if isinstance(bundle.data['modified_on'], (int, long)):
                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.request.user:
                bundle.data['user']=bundle.request.user
            if bundle.data.has_key('idea'):
                idea= bundle.data['idea']
                try:
                    idea = Idea.actives.filter(user=bundle.request.user.id).get(id=idea)
                    bundle.data['idea'] = idea
                except ObjectDoesNotExist:
                    raise BadRequest('idea not found')
            if bundle.data.has_key('image'):
                image_id=bundle.data['image']
                try:
                    image = Image.objects.get(id=image_id)
                    if image.user != bundle.request.user:
                        raise BadRequest('image not authorized')
                    else:
                        bundle.obj.image=image
                except ObjectDoesNotExist:
                    image = Image(id=image_id, user = bundle.request.user)
                    image.save()
                    bundle.obj.image=image
        elif bundle.request.method == 'PUT' or bundle.request.method == 'PATCH':
            print 'update'
            if bundle.request.user and bundle.data.has_key('id') and bundle.data.has_key('revision'):
                bundle.data['user']=bundle.request.user
                id= str(bundle.data['id'])
                revision = int(bundle.data['revision'])
                try:
                    snapshot = Snapshot.actives.filter(user=bundle.request.user.id).filter(revision=revision).get(id=id)
                    bundle.data['idea']=snapshot.idea
                except ObjectDoesNotExist:
                    raise BadRequest('not authorized')
                if bundle.data.has_key('ordering'):
                    snapshot.update_order(bundle.data['ordering'])
                    del bundle.data['ordering']
                if bundle.data.has_key('image'):
                    image_id=bundle.data['image']
                    if not snapshot.image or not snapshot.image.pk == image_id:
                        try:
                            image = Image.objects.get(id=image_id)
                            if image.user != bundle.request.user:
                                raise BadRequest('image not authorized')
                            else:
                                snapshot.image=image
                                snapshot.save()
                        except ObjectDoesNotExist:
                            image = Image(id=image_id, user = bundle.request.user)
                            image.save()
                            snapshot.image=image
                            snapshot.save()
#                        bundle.data['image']=image
                return bundle
            raise ImmediateHttpResponse(
                HttpForbidden("Check ID")
            )
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['idea'] = bundle.obj.idea.id
        bundle.data['user'] =  bundle.obj.user.id
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        bundle.data['modified_on'] = convertDate(bundle.obj.modified_on)
        if bundle.obj.image:
            bundle.data['image'] = bundle.obj.image.id
            if bundle.obj.image.original_image:
                bundle.data['original_image'] = bundle.obj.image.original_image.url
                bundle.data['tile_image'] = bundle.obj.image.tile_image.url
                bundle.data['icon_image'] = bundle.obj.image.icon_image.url
        if not bundle.obj.is_active:
            bundle.data['destroy']= True
        return bundle

class QuestionResource(ModelResource):
    user = fields.ForeignKey(UserResource, 'user')#, null=True
    idea = fields.ForeignKey(IdeaResource, 'idea')

    class Meta:
        queryset = Question.actives.annotate(rank=Sum('supportquestion__up_rank')).order_by('-rank')#.annotate(num_answers=Count('answer')).order_by('-rank')
        resource_name = 'question'
        excludes = ['is_active']
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['id', 'resource_uri', 'text', 'revision','is_active']
        excludes = []
        allowed_methods = ['get','post','put','patch']
        filtering = {
            "user": ('exact'),
            "idea": ('exact')
        }
        ordering = [
            'modified_on',
        ]
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        bundle = preHydrate(bundle)
        #convert javascript timestamp to python datetime
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.data.has_key('modified_on'):
            if isinstance(bundle.data['modified_on'], (int, long)):
                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.request.user:
                bundle.data['user']=bundle.request.user
            if bundle.data.has_key('idea'):
                idea= bundle.data['idea']
                try:
                    idea = Idea.actives.get(id=idea)
                    bundle.data['idea'] = idea
                except ObjectDoesNotExist:
                    raise BadRequest('idea not found')
        elif bundle.request.method == 'PUT' or bundle.request.method == 'PATCH':
            if bundle.data.has_key('id') and bundle.data.has_key('revision'):
                id= bundle.data['id']
                revision = bundle.data['revision']
                try:
                    question = Question.actives.filter(user=bundle.request.user.id).filter(revision=revision).get(id=id)
                    bundle.data['idea']=question.idea
                    return bundle
                except ObjectDoesNotExist:
                    raise BadRequest('not authorized')
            raise ImmediateHttpResponse(
                HttpForbidden("Check ID")
            )
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['idea']=bundle.obj.idea.id
        user = bundle.obj.user
        bundle.data['user'] =  user.id
        bundle.data['username'] =  user.username
        user_img = user.profile.profile_image.icon_image.url
        if user_img:
            bundle.data['user_icon_image'] = user_img
        bundle.data['is_owner'] = bundle.obj.user == bundle.obj.idea.user
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        bundle.data['modified_on'] = convertDate(bundle.obj.modified_on)
        ranking = supportQuestion.actives.filter(question=bundle.obj)
        bundle.data['rank']=ranking.filter(up_rank=1).count()-ranking.filter(up_rank=-1).count()
        if bundle.request.user and not bundle.request.user.is_anonymous():
            user_ranking = ranking.filter(supporter=bundle.request.user)
            if user_ranking.exists():
                if user_ranking.all().order_by('-pk')[0].up_rank:
                    bundle.data['is_ranked']=1
                else:
                    bundle.data['is_ranked']=-1
            else:
                bundle.data['is_ranked']=0
        answer = Answer.actives.filter(question=bundle.obj).annotate(rank=Sum('supportanswer__up_rank')).order_by('-rank')
        answer_values = answer.values('id','user__username', 'user' ,'text','rank')[:1]
        temp = []
        for i in answer_values:
            i['is_owner'] = i['user__username'] == bundle.obj.idea.user.username
            i['user']=i['user']
            i['username']=i['user__username']
            ans_ranking = supportAnswer.actives.filter(answer__id=i['id'])
            i['rank']=ans_ranking.filter(up_rank=1).count()-ans_ranking.filter(up_rank=-1).count()
            del i['user__username']
            if bundle.request.user and not bundle.request.user.is_anonymous():
                ans_user_ranking = ans_ranking.filter(supporter=bundle.request.user)
                if ans_user_ranking.exists():
                    if ans_user_ranking.all().order_by('-pk')[0].up_rank:
                        i['is_ranked']=1
                    else:
                        i['is_ranked']=-1
            else:
                i['is_ranked']=0
            temp.append(i)
        bundle.data['preview_answers'] = temp
        bundle.data['count_answers'] = answer.count()
        return bundle

class AnswerResource(ModelResource):
    user = fields.ForeignKey(UserResource, 'user')#, null=True
    idea = fields.ForeignKey(IdeaResource, 'idea')
    question = fields.ForeignKey(QuestionResource, 'question')

    class Meta:
        queryset = Answer.actives.annotate(rank=Sum('supportanswer__up_rank')).order_by('-rank')#.all().order_by('-modified_on')
        resource_name = 'answer'
        excludes = ['is_active']
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['id', 'resource_uri', 'text', 'revision','is_active']
        excludes = []
        allowed_methods = ['get','post']
        filtering = {
            "user": ('exact'),
            "idea": ('exact'),
            "question":('exact')
        }
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        bundle = preHydrate(bundle)
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.data.has_key('modified_on'):
            if isinstance(bundle.data['modified_on'], (int, long)):
                bundle.data['modified_on'] = datetime.fromtimestamp(bundle.data['modified_on']/1000.0)
        if bundle.request.method == 'POST':
#            if bundle.data.has_key('id'):
#                del bundle.data['id']
            if bundle.request.user:
                bundle.data['user']=bundle.request.user
            if bundle.data.has_key('question'):
                question= bundle.data['question']
                try:
                    question = Question.actives.get(id=question)
                    bundle.data['question'] = question
                    bundle.data['idea'] = question.idea
                except ObjectDoesNotExist:
                    raise BadRequest('idea not found')
#        elif bundle.request.method == 'PUT' or bundle.request.method == 'PATCH':
#            if bundle.data.has_key('id') and bundle.data.has_key('revision'):
#                id= bundle.data['id']
#                revision = bundle.data['revision']
#                try:
#                    question = Question.actives.filter(user=bundle.request.user.id).filter(revision=revision).get(id=id)
#                    bundle.data['idea']=question.idea
#                    return bundle
#                except ObjectDoesNotExist:
#                    raise BadRequest('not authorized')
#            raise ImmediateHttpResponse(
#                HttpForbidden("Check ID")
#            )
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['idea']=bundle.obj.idea.id
        bundle.data['question']=bundle.obj.question.id
        user = bundle.obj.user
        bundle.data['user'] =  user.id
        bundle.data['username'] =  user.username
        user_img = user.profile.profile_image.icon_image.url
        if user_img:
            bundle.data['user_icon_image'] = user_img
        bundle.data['is_owner'] = bundle.obj.user == bundle.obj.idea.user
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        bundle.data['modified_on'] = convertDate(bundle.obj.modified_on)
        ranking = supportAnswer.actives.filter(answer=bundle.obj)
        bundle.data['rank']=ranking.filter(up_rank=1).count()-ranking.filter(up_rank=-1).count()
        if bundle.request.user and not bundle.request.user.is_anonymous():
            user_ranking = ranking.filter(supporter=bundle.request.user)
            if user_ranking.exists():
                if user_ranking.all().order_by('-pk')[0].up_rank:
                    bundle.data['is_ranked']=1
                else:
                    bundle.data['is_ranked']=-1
            else:
                bundle.data['is_ranked']=0
        return bundle

class FollowingResource(ModelResource):
    user = fields.ForeignKey(ProfileResource, 'user')#, null=True
    supporter = fields.ForeignKey(ProfileResource, 'supporter')

    class Meta:
        queryset = supportUser.actives.all().order_by('-pk')
        resource_name = 'following'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['is_active']
        allowed_methods = ['get','post']
        filtering = {
#            "user": ('exact'),
            "supporter": ('exact'),
        }
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.data.has_key('user') and bundle.request.user:
                bundle.data['supporter'] = bundle.request.user.get_profile()
                user = bundle.data['user']
                try:
                    user = User.objects.get(id=user)
                    bundle.data['user'] = user.get_profile()
                except ObjectDoesNotExist:
                    raise BadRequest('idea not found')
                si = supportUser.objects.filter(user=user).filter(supporter=bundle.request.user.pk)
                if si.exists():
                    bundle.obj =  si.all()[0]
            else:
                raise BadRequest('idea and user not found')
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        if not bundle.request.user.is_anonymous():
            bundle.data['is_following'] =  supportUser.actives.filter(supporter = bundle.request.user.pk).filter(user = bundle.obj.user.pk).exists()
        bundle.data['user'] =  bundle.obj.user.user.id
        bundle.data['username'] =  bundle.obj.user.user.username
        bundle.data['bio'] =  bundle.obj.user.bio
        bundle.data['display_name'] =  bundle.obj.user.display_name
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        bundle.data['count_ideas'] = Idea.actives.filter(user=bundle.obj.user.pk).count()
        bundle.data['count_followers'] = supportUser.actives.filter(user=bundle.obj.user.pk).count()
        return bundle

class FollowerResource(ModelResource):
    user = fields.ForeignKey(UserResource, 'user')#, null=True
    supporter = fields.ForeignKey(UserResource, 'supporter')

    class Meta:
        queryset = supportUser.actives.all().order_by('-pk')
        resource_name = 'follower'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['id']
        allowed_methods = ['get']
        filtering = {
            "user": ('exact'),
#            "supporter": ('exact'),
        }
        always_return_data = True

    def dehydrate(self, bundle):
        if not bundle.request.user.is_anonymous():
            bundle.data['is_following'] =  supportUser.actives.filter(supporter = bundle.request.user.pk).filter(user = bundle.obj.supporter.pk).exists()
        bundle.data['user'] =  bundle.obj.supporter.user.id
        bundle.data['username'] =  bundle.obj.supporter.user.username
        bundle.data['bio'] =  bundle.obj.supporter.bio
        bundle.data['display_name'] =  bundle.obj.supporter.display_name
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        bundle.data['count_ideas'] = Idea.actives.filter(user=bundle.obj.supporter.pk).count()
        bundle.data['count_followers'] = supportUser.actives.filter(user=bundle.obj.supporter.pk).count()
        return bundle

class SupportResource(ModelResource):
    idea = fields.ForeignKey(IdeaResource, 'idea')
#    user = fields.ForeignKey(UserResource, 'user', null=True)#
    supporter = fields.ForeignKey(UserResource, 'supporter')

    class Meta:
        queryset = supportIdea.objects.all().order_by('-pk')
        resource_name = 'support'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['is_active']
        allowed_methods = ['get','post']
        filtering = {
            "supporter": ('exact'),
            "idea": ('exact')
        }
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.data.has_key('idea') and bundle.request.user:
                bundle.data['supporter'] = bundle.request.user
                idea = bundle.data['idea']
                si = supportIdea.objects.filter(idea=idea).filter(supporter=bundle.request.user)
                if si.exists():
                    bundle.obj = si.all()[0]
                try:
                    idea = Idea.actives.get(id=idea)
                    bundle.data['idea'] = idea
                except ObjectDoesNotExist:
                    raise BadRequest('idea not found')
            else:
                raise BadRequest('idea and user not found')
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['idea'] =  bundle.obj.idea.id
        bundle.data['supporter'] =  bundle.obj.supporter.username
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        return bundle

class QuestionRankResource(ModelResource):
    question = fields.ForeignKey(QuestionResource, 'question')
#    user = fields.ForeignKey(UserResource, 'user', null=True)#
    supporter = fields.ForeignKey(UserResource, 'supporter')

    class Meta:
        queryset = supportQuestion.objects.all().order_by('-pk')
        resource_name = 'question-rank'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['is_active', 'up_rank']
        allowed_methods = ['get','post']
        filtering = {
            "supporter": ('exact'),
            "question": ('exact')
        }
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.data.has_key('question') and bundle.request.user:
                bundle.data['supporter'] = bundle.request.user
                question = bundle.data['question']
                si = supportQuestion.objects.filter(question=question).filter(supporter=bundle.request.user)
                if si.exists():
                    bundle.obj =  si.all()[0]
                try:
                    q = Question.actives.get(id=question)
                    bundle.data['question'] = q
                except ObjectDoesNotExist:
                    raise BadRequest('question not found')
            else:
                raise BadRequest('question and user not found')
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['question'] =  bundle.obj.question.id
        bundle.data['supporter'] =  bundle.obj.supporter.username
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        return bundle

class AnswerRankResource(ModelResource):
    answer = fields.ForeignKey(AnswerResource, 'answer')
    #    user = fields.ForeignKey(UserResource, 'user', null=True)#
    supporter = fields.ForeignKey(UserResource, 'supporter')

    class Meta:
        queryset = supportAnswer.objects.all().order_by('-pk')
        resource_name = 'answer-rank'
        authorization = Authorization()
        authentication = AnonymousApiKeyAuthentication()
        fields = ['is_active', 'up_rank']
        allowed_methods = ['get','post']
        filtering = {
            "supporter": ('exact'),
            "answer": ('exact')
        }
        always_return_data = True

    def hydrate(self, bundle):
        if bundle.data.has_key('processed'):
            return bundle
        else:
            bundle.data['processed'] = True
        if bundle.data.has_key('created_on'):
            if isinstance(bundle.data['created_on'], (int, long)):
                bundle.data['created_on'] = datetime.fromtimestamp(bundle.data['created_on']/1000.0)
        if bundle.request.method == 'POST':
            if bundle.data.has_key('answer') and bundle.request.user:
                bundle.data['supporter'] = bundle.request.user
                answer = bundle.data['answer']
                si = supportAnswer.objects.filter(answer=answer).filter(supporter=bundle.request.user)
                if si.exists():
                    bundle.obj =  si.all()[0]
                try:
                    bundle.data['answer'] = Answer.actives.get(id=answer)
                except ObjectDoesNotExist:
                    raise BadRequest('answer not found')
            else:
                raise BadRequest('answer and user not found')
        return bundle

    def dehydrate(self, bundle):
        if bundle.data.has_key('processed'):
            del bundle.data['processed']
        bundle.data['answer'] =  bundle.obj.answer.id
        bundle.data['supporter'] =  bundle.obj.supporter.username
        bundle.data['created_on'] = convertDate(bundle.obj.created_on)
        return bundle

v1 = Api(api_name='v1')
v1.register(ProfileResource())
v1.register(UserResource())
#v1.register(ManageSelfResource())
v1.register(IdeaResource())
v1.register(SnapshotResource())
v1.register(QuestionResource())
v1.register(AnswerResource())
#v1.register(ImageResource())
v1.register(FollowingResource())
v1.register(FollowerResource())
v1.register(SupportResource())
v1.register(QuestionRankResource())
v1.register(AnswerRankResource())
v1.register(SocialAuthResource())

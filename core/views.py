from django.template import RequestContext
from django.shortcuts import render_to_response
from random import choice
from django.contrib.auth.decorators import login_required
from string import letters
from django.http import HttpResponseRedirect, HttpResponseBadRequest, HttpResponse
from django.utils import simplejson
from django.views.decorators.csrf import csrf_exempt
from django.contrib import auth
from django.contrib.auth.views import password_reset
from models import *
from tastypie.models import ApiKey
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.storage import default_storage
from django.contrib.sessions.models import Session
from django.core.validators import email_re
from django.contrib.auth import logout
from datetime import datetime, timedelta
import calendar
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import int_to_base36, base36_to_int
from django.contrib.sites.models import get_current_site
from django.template import loader
from django.core.mail import send_mail
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.template.defaultfilters import slugify

def is_valid_email(email):
    return True if email_re.match(email) else False

def CrossSiteResponse(res):
    res['Access-Control-Allow-Origin'] = "*"
    res["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    res["Access-Control-Max-Age"] = "1000"
    res["Access-Control-Allow-Headers"] = "*"
    return res
#
##@csrf_exempt
#def postTest(request):
#    html = "<html><body>It is now.</body></html>"
#    res = HttpResponse(html)
#    user = User.objects.get(id=1)
#    auth_key = TempAuth.objects.createTempAuth(user)
#    return CrossSiteResponse(HttpResponseBadRequest('Check permission'))

def postImage(request):
    if request.method == "OPTIONS":
        response = HttpResponse()
        return CrossSiteResponse(response)
    if request.method == 'POST':
        if request.GET.__contains__('userid') and request.GET.__contains__('authkey'):
            auth_key = request.GET.get('authkey')
            user_id = request.GET.get('userid')
            try:
                TempAuth.objects.filter(user__id=user_id).filter(expiration_date__gte=datetime.now).get(hash_key=auth_key)
                #                api = ApiKey.objects.filter(user__username=request.GET.get('username')).get(key = request.GET.get('api_key'))
                user = User.objects.get(id = user_id)
            except ObjectDoesNotExist:
                return CrossSiteResponse(HttpResponseBadRequest('Check permission'))
        else:
            return CrossSiteResponse(HttpResponseBadRequest('Check permission'))
        # settings for the file upload
        #   you can define other parameters here
        #   and check validity late in the code
        options = {
            # the maximum file size (must be in bytes)
            "maxfilesize": 10 * 2 ** 20, # 10 Mb
            # the minimum file size (must be in bytes)
            "minfilesize": 1 * 2 ** 10, # 1 Kb
            # the file types which are going to be allowed for upload
            #   must be a mimetype
            "acceptedformats": (
                "image/jpeg",
                "image/png",
                )
        }
        if not request.FILES:
            return CrossSiteResponse(HttpResponseBadRequest('Must have files attached!'))

        #getting file data for farther manipulations
        file = request.FILES[u'file']

        # initialize the error
        # If error occurs, this will have the string error message so
        # uploader can display the appropriate message
        error = False
        # check against options for errors
        # file size
        if file.size > options["maxfilesize"]:
            print 'file too big'
            error = "maxFileSize"
        if file.size < options["minfilesize"]:
            error = "minFileSize"
            # allowed file type
        if file.content_type not in options["acceptedformats"]:
            error = "acceptFileTypes"
        # the response data which will be returned to the uploader as json
        response_data = {
            "name": file.name,
            "size": file.size,
            "type": file.content_type
        }

        # if there was an error, add error message to response_data and return
        if error:
            # append error message
            response_data["error"] = error
            # generate json
            response_data = simplejson.dumps([response_data])
            # return response to uploader with error
            # so it can display error message
            return CrossSiteResponse(HttpResponse(response_data, mimetype='application/json'))

            # figure out the path where files will be uploaded to
        #        temp_path = os.path.join(settings.MEDIA_ROOT, "image_upload")
#        timestamp=calendar.timegm(datetime.utcnow().utctimetuple())
#        temp_path = "/image_upload/"+str(user_id)+'/'+timestamp+'-'+file.name
#        saved_file=default_storage.save(temp_path, file)
        if request.POST.__contains__('id'):
            image_id=request.POST.get('id')
            try:
                image = Image.objects.get(id=image_id)
                if image.user != user:
                    return CrossSiteResponse(HttpResponseBadRequest('Check user'))
            except ObjectDoesNotExist:
                image=Image(pk=image_id, user=user)
        else:
            image = Image(user=user)
#        image.original_image=saved_file
        image.original_image=file
        image.filename=str(file.name)
        image.save()
    # url the file in case user decides to delete it
        #        response_data["url"] = url
        response_data["id"] = image.pk
        response_data["original_image"] = image.original_image.url
        response_data["tile_image"] = image.tile_image.url
#        response_data["thumbnail_url"] = im.thumbnail.url
        # url for deleting the file in case user decides to delete it
#        response_data["delete_url"] = request.path + "?"+ urllib.urlencode({"apk": a.pk,'ipk':im.pk})
        # specify the delete type - must be POST for csrf
#        response_data["delete_type"] = "GET"

        # generate the json data
        response_data = simplejson.dumps([response_data])
        # response type
        response_type = "application/json"
        # return the data to the uploading plugin
        return CrossSiteResponse(HttpResponse(response_data, mimetype=response_type))
    return CrossSiteResponse(HttpResponseBadRequest('Check request'))

def logoutView(request):
    logout(request)

def isUnique(request):
    response_data ={}
    if request.GET.__contains__('username'):
        username = request.GET.get('username').lower().strip()
        if User.objects.filter(username__exact=username).exists() or reservedUsername.objects.filter(username__exact=username).exists():
            response_data["username"] = False
        else:
            response_data["username"] = True
    if request.GET.__contains__('email'):
        email = request.GET.get('email').lower().strip()
        if not is_valid_email(email):
            response_data["email"] = False
        elif User.objects.filter(email__exact=email).exists():
            response_data["email"] = False
        else:
            response_data["email"] = True
    response_data = simplejson.dumps([response_data])
    return HttpResponse(response_data, mimetype='application/json')

def authUser(request):
    apikey=''
    if request.META.has_key('HTTP_AUTHORIZATION'):
        auth_meth, auth_str = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
        if auth_meth.lower() == 'basic':
            auth_str = auth_str.strip().decode('base64')
            username, password = auth_str.split(':', 1)
            user = auth.authenticate(username=username, password=password)
            if user:
                api_key = ApiKey.objects.get(user=user).key
                auth_key = TempAuth.objects.createTempAuth(user)
                return render_to_response('login.html',{'api_key':api_key, 'auth_key':auth_key,'user':user},context_instance=RequestContext(request))
            else:
                return HttpResponse(status=401)
#    username = request.POST.get('username', '')
#    password = request.POST.get('password', '')
#    user = auth.authenticate(username=username, password=password)
#    if user is not None and user.is_active:
        # Correct password, and the user is marked "active"
#        auth.login(request, user)
        # Redirect to a success page.
#        if request.POST.__contains__('next'):
#            return HttpResponseRedirect(request.POST['next'])
#        return HttpResponseRedirect("/")

#    else:
        # Show an error page
#        return HttpResponseRedirect("/accounts/login/")

def join(request):
    if request.method == 'POST':
        data = request.POST.copy() # so we can manipulate data
        email = data['email']
        password = data['password']
        username = ''
        if is_valid_email(email) and User.objects.filter(email=email).count() == 0:
            username = slugify(email.strip().lower().partition('@')[0][:30])
            if User.objects.filter(username__exact=username).exists() or reservedUsername.objects.filter(username__exact=username).exists():
                username = slugify(''.join([choice(letters) for i in xrange(30)]))
        try:
            user = User.objects.create_user(username, email, password)
            profile = Profile.objects.create(user = user)
        except BaseException:
            return HttpResponse(status=409) #conflict user exists
        user = auth.authenticate(username=username, password=password)
        if user:
            api_key = ApiKey.objects.get(user=user).key
            auth_key = TempAuth.objects.createTempAuth(user)
            return render_to_response('login.html',{'api_key':api_key, 'auth_key':auth_key,'user':user},context_instance=RequestContext(request))
        else:
            return HttpResponse(status=401)
    else:
        return HttpResponse(status=405) #other methods not allowed

def resetPassword(request,
                       email_template_name='registration/password_reset_email.html',
                       subject_template_name='registration/password_reset_subject.txt',
                       password_reset_form=PasswordResetForm,
                       token_generator=default_token_generator,
                       from_email='admin@tinkermob.com',
                       current_app=None,
                       extra_context=None):
        if request.method == "POST":
            if not request.POST.__contains__('email'):
                return HttpResponse(status=401)
            e = request.POST.get('email').strip()
            users = User.objects.filter(email__iexact=e)
            if not len(users):
                return HttpResponse(status=401)
            if not any(user.is_active for user in users):
                # none of the filtered users are active
                print 'active'
                return HttpResponse(status=401)
            """
            Generates a one-use only link for resetting password and sends to the
            user.
            """
            for user in users:
                current_site = get_current_site(request)
                site_name = current_site.name
                domain = current_site.domain
                c = {
                    'email': user.email,
                    'domain': domain,
                    'site_name': site_name,
                    'uid': int_to_base36(user.pk),
                    'user': user,
                    'token': token_generator.make_token(user),
                    'protocol': request.is_secure() and 'https' or 'http',
                    }
                subject = loader.render_to_string(subject_template_name, c)
                # Email subject *must not* contain newlines
                subject = ''.join(subject.splitlines())
                email = loader.render_to_string(email_template_name, c)
                send_mail(subject, email, from_email, [user.email])
            return HttpResponse(status=200)
        return HttpResponse(status=401)

@sensitive_post_parameters()
@never_cache
def passwordResetConfirm(request, uidb36=None, token=None,
                           token_generator=default_token_generator):
    """
    View that checks the hash in a password reset link and presents a
    form for entering a new password.
    """
    print uidb36
    print token
    assert uidb36 is not None and token is not None  # checked by URLconf
    try:
        uid_int = base36_to_int(uidb36)
        user = User.objects.get(pk=uid_int)
    except (ValueError, OverflowError, User.DoesNotExist):
        user = None
        return HttpResponse(status=401)
    if user is not None and token_generator.check_token(user, token):
        print user.email
        api_key = ApiKey.objects.get(user=user).key
        auth_key = TempAuth.objects.createTempAuth(user)
        return render_to_response('login.html',{'api_key':api_key, 'auth_key':auth_key,'user':user},context_instance=RequestContext(request))
    else:
        return HttpResponse(status=401)
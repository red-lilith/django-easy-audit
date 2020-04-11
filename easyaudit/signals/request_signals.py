from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.signals import request_started
from django.http.cookie import SimpleCookie
from django.utils import timezone
from django.conf import settings
from easyaudit.models import RequestEvent
from easyaudit.settings import REMOTE_ADDR_HEADER, UNREGISTERED_URLS, REGISTERED_URLS, WATCH_REQUEST_EVENTS
import re


def should_log_url(url):
    # check if current url is blacklisted
    for unregistered_url in UNREGISTERED_URLS:
        pattern = re.compile(unregistered_url)
        if pattern.match(url):
            return False

    # only audit URLs listed in REGISTERED_URLS (if it's set)
    if len(REGISTERED_URLS) > 0:
        for registered_url in REGISTERED_URLS:
            pattern = re.compile(registered_url)
            if pattern.match(url):
                return True
        return False

    # all good    
    return True

# Replacing environ -> scope in asgi 
def request_started_handler(sender, scope, **kwargs):
    if not should_log_url(scope['path']):
        return

    # get the user from cookies
    user = None
    headers = dict((x.decode('utf-8'), y.decode('utf-8')) for x, y in scope['headers'])
    if headers.get('cookie'):
        cookie = SimpleCookie() # python3 compatibility
        cookie.load(headers['cookie'])

        session_cookie_name = settings.SESSION_COOKIE_NAME
        if session_cookie_name in cookie:
            session_id = cookie[session_cookie_name].value

            try:
                session = Session.objects.get(session_key=session_id)
            except Session.DoesNotExist:
                session = None

            if session:
                user_id = session.get_decoded().get('_auth_user_id')
                try:
                    user = get_user_model().objects.get(id=user_id)
                except:
                    user = None

    request_event = RequestEvent.objects.create(
        url=scope['path'],
        method=scope['method'],
        query_string=scope['query_string'].decode('utf-8'),
        user_id=getattr(user, 'id', None),
        remote_ip=scope['client'][0],
        datetime=timezone.now()
    )


if WATCH_REQUEST_EVENTS:
    request_started.connect(request_started_handler, dispatch_uid='easy_audit_signals_request_started')

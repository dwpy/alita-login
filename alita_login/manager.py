# -*- coding: utf-8 -*-

from datetime import datetime
from .config import *
from .mixins import AnonymousUserMixin
from .signals import (user_loaded_from_cookie, user_loaded_from_header,
                      user_loaded_from_request, user_unauthorized,
                      user_needs_refresh, user_accessed, session_protected)
from .utils import (login_url as make_login_url, _create_identifier,
                    _user_context_processor, encode_cookie, decode_cookie,
                    make_next_param, expand_login_view)
from alita.exceptions import abort
from alita import RedirectResponse


class LoginManager(object):
    '''This object is used to hold the settings used for logging in. Instances
    of :class:`LoginManager` are *not* bound to specific apps, so you can
    create one in the main body of your code and then bind it to your
    app in a factory function.
    '''
    def __init__(self, app=None, add_context_processor=True, login_view=None):
        self.app = None
        #: A class or factory function that produces an anonymous user, which
        #: is used when no one is logged in.
        self.anonymous_user = AnonymousUserMixin

        #: The name of the view to redirect to when the user needs to log in.
        #: (This can be an absolute URL as well, if your authentication
        #: machinery is external to your application.)
        self.login_view = login_view

        #: Names of views to redirect to when the user needs to log in,
        #: per blueprint. If the key value is set to None the value of
        #: :attr:`login_view` will be used instead.
        self.blueprint_login_views = {}

        #: The message to flash when a user is redirected to the login page.
        self.login_message = LOGIN_MESSAGE

        #: The message category to flash when a user is redirected to the login
        #: page.
        self.login_message_category = LOGIN_MESSAGE_CATEGORY

        #: The name of the view to redirect to when the user needs to
        #: reauthenticate.
        self.refresh_view = None

        #: The message to flash when a user is redirected to the 'needs
        #: refresh' page.
        self.needs_refresh_message = REFRESH_MESSAGE

        #: The message category to flash when a user is redirected to the
        #: 'needs refresh' page.
        self.needs_refresh_message_category = REFRESH_MESSAGE_CATEGORY

        #: The mode to use session protection in. This can be either
        #: ``'basic'`` (the default) or ``'strong'``, or ``None`` to disable
        #: it.
        self.session_protection = 'basic'

        #: If present, used to translate flash messages ``self.login_message``
        #: and ``self.needs_refresh_message``
        self.localize_callback = None

        self.unauthorized_callback = None

        self.needs_refresh_callback = None

        self.id_attribute = ID_ATTRIBUTE

        self._user_callback = None

        self._header_callback = None

        self._request_callback = None

        self._session_identifier_generator = _create_identifier

        if app is not None:
            self.init_app(app, add_context_processor)

    def init_app(self, app, add_context_processor=True):
        self.app = app
        self.app.login_manager = self
        self.app.response_middleware(self._update_remember_cookie)

        if add_context_processor:
            self.app.context_processor(_user_context_processor)

        @self.app.request_middleware
        async def process_request(request):
            self._load_user(request)

    def unauthorized(self, request):
        '''
        This is called when the user is required to log in. If you register a
        callback with :meth:`LoginManager.unauthorized_handler`, then it will
        be called. Otherwise, it will take the following actions:
            - Flash :attr:`LoginManager.login_message` to the user.
            - If the app is using blueprints find the login view for
              the current blueprint using `blueprint_login_views`. If the app
              is not using blueprints or the login view for the current
              blueprint is not specified use the value of `login_view`.
            - Redirect the user to the login view. (The page they were
              attempting to access will be passed in the ``next`` query
              string variable, so you can redirect there if present instead
              of the homepage. Alternatively, it will be added to the session
              as ``next`` if USE_SESSION_FOR_NEXT is set.)
        If :attr:`LoginManager.login_view` is not defined, then it will simply
        raise a HTTP 401 (Unauthorized) error instead.
        This should be returned from a view or before/after_request function,
        otherwise the redirect will have no effect.
        '''
        user_unauthorized.send(self.app)

        if self.unauthorized_callback:
            return self.unauthorized_callback(request)

        if request.blueprint in self.blueprint_login_views:
            login_view = self.blueprint_login_views[request.blueprint]
        else:
            login_view = self.login_view

        if not login_view:
            abort(401)

        if self.app.config.get('USE_SESSION_FOR_NEXT', USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(self.app, login_view)
            request.session[AUTH_ID] = self._session_identifier_generator(request)
            request.session[AUTH_NEXT] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(self.app, login_view)
        else:
            redirect_url = make_login_url(self.app, login_view, next_url=request.url)

        return RedirectResponse(redirect_url)

    def user_loader(self, callback):
        '''
        This sets the callback for reloading a user from the session. The
        function you set should take a user ID (a ``unicode``) and return a
        user object, or ``None`` if the user does not exist.
        :param callback: The callback for retrieving a user object.
        :type callback: callable
        '''
        self._user_callback = callback
        return callback

    def header_loader(self, callback):
        '''
        This function has been deprecated. Please use
        :meth:`LoginManager.request_loader` instead.
        This sets the callback for loading a user from a header value.
        The function you set should take an authentication token and
        return a user object, or `None` if the user does not exist.
        :param callback: The callback for retrieving a user object.
        :type callback: callable
        '''
        print('LoginManager.header_loader is deprecated. Use ' +
              'LoginManager.request_loader instead.')
        self._header_callback = callback
        return callback

    def request_loader(self, callback):
        '''
        This sets the callback for loading a user from a Alita request.
        The function you set should take Alita request object and
        return a user object, or `None` if the user does not exist.
        :param callback: The callback for retrieving a user object.
        :type callback: callable
        '''
        self._request_callback = callback
        return callback

    def unauthorized_handler(self, callback):
        '''
        This will set the callback for the `unauthorized` method, which among
        other things is used by `login_required`. It takes no arguments, and
        should return a response to be sent to the user instead of their
        normal view.
        :param callback: The callback for unauthorized users.
        :type callback: callable
        '''
        self.unauthorized_callback = callback
        return callback

    def needs_refresh_handler(self, callback):
        '''
        This will set the callback for the `needs_refresh` method, which among
        other things is used by `fresh_login_required`. It takes no arguments,
        and should return a response to be sent to the user instead of their
        normal view.
        :param callback: The callback for unauthorized users.
        :type callback: callable
        '''
        self.needs_refresh_callback = callback
        return callback

    def needs_refresh(self, request):
        '''
        This is called when the user is logged in, but they need to be
        reauthenticated because their session is stale. If you register a
        callback with `needs_refresh_handler`, then it will be called.
        Otherwise, it will take the following actions:
            - Flash :attr:`LoginManager.needs_refresh_message` to the user.
            - Redirect the user to :attr:`LoginManager.refresh_view`. (The page
              they were attempting to access will be passed in the ``next``
              query string variable, so you can redirect there if present
              instead of the homepage.)
        If :attr:`LoginManager.refresh_view` is not defined, then it will
        simply raise a HTTP 401 (Unauthorized) error instead.
        This should be returned from a view or before/after_request function,
        otherwise the redirect will have no effect.
        '''
        user_needs_refresh.send(self.app)

        if self.needs_refresh_callback:
            return self.needs_refresh_callback(request)

        if not self.refresh_view:
            abort(401)

        config = self.app.config
        if config.get('USE_SESSION_FOR_NEXT', USE_SESSION_FOR_NEXT):
            login_url = expand_login_view(self.app, self.refresh_view)
            request.session[AUTH_ID] = self._session_identifier_generator(request)
            request.session[AUTH_NEXT] = make_next_param(login_url, request.url)
            redirect_url = make_login_url(self.app, self.refresh_view)
        else:
            login_url = self.refresh_view
            redirect_url = make_login_url(self.app, login_url, next_url=request.url)

        return RedirectResponse(redirect_url)

    def _update_request_context_with_user(self, request, user=None):
        request.user = self.anonymous_user() if user is None else user

    def _load_user(self, request):
        '''Loads user from session or remember_me cookie as applicable'''

        if self._user_callback is None and self._request_callback is None:
            raise Exception("Missing user_loader or request_loader.")

        user_accessed.send(self.app)

        # Check SESSION_PROTECTION
        if self._session_protection_failed(request):
            return self._update_request_context_with_user(request)

        user = None

        # Load user from Alita Session
        user_id = request.session.get(AUTH_USER_ID)
        if user_id is not None and self._user_callback is not None:
            user = self._user_callback(user_id)

        # Load user from Remember Me Cookie or Request Loader
        if user is None:
            config = self.app.config
            cookie_name = config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
            header_name = config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)
            has_cookie = (cookie_name in request.cookies and
                          request.session.get(AUTH_USER_REMEMBER) != 'clear')
            if has_cookie:
                cookie = request.cookies[cookie_name]
                user = self._load_user_from_remember_cookie(request, cookie)
            elif self._request_callback:
                user = self._load_user_from_request(request)
            elif header_name in request.headers:
                header = request.headers[header_name]
                user = self._load_user_from_header(header)

        return self._update_request_context_with_user(request, user)

    def _session_protection_failed(self, request):
        sess = request.session
        ident = self._session_identifier_generator(request)

        mode = self.app.config.get('SESSION_PROTECTION', self.session_protection)

        if not mode or mode not in ['basic', 'strong']:
            return False

        # if the sess is empty, it's an anonymous user or just logged out
        # so we can skip this
        if sess and ident != sess.get(AUTH_ID, None):
            if mode == 'basic' or sess.permanent:
                sess[AUTH_USER_FRESH] = False
                session_protected.send(self.app)
                return False
            elif mode == 'strong':
                for k in SESSION_KEYS:
                    sess.pop(k, None)

                sess[AUTH_USER_REMEMBER] = 'clear'
                session_protected.send(self.app)
                return True

        return False

    def _load_user_from_remember_cookie(self, request, cookie):
        user_id = decode_cookie(cookie)
        if user_id is not None:
            request.session[AUTH_USER_ID] = user_id
            request.session[AUTH_USER_FRESH] = False
            user = None
            if self._user_callback:
                user = self._user_callback(user_id)
            if user is not None:
                user_loaded_from_cookie.send(self.app, user=user)
                return user
        return None

    def _load_user_from_header(self, header):
        if self._header_callback:
            user = self._header_callback(header)
            if user is not None:
                user_loaded_from_header.send(self.app, user=user)
                return user
        return None

    def _load_user_from_request(self, request):
        if self._request_callback:
            user = self._request_callback(request)
            if user is not None:
                user_loaded_from_request.send(self.app, user=user)
                return user
        return None

    def _update_remember_cookie(self, request, response):
        # Don't modify the session unless there's something to do.
        if AUTH_USER_REMEMBER not in request.session and \
                self.app.config.get('REMEMBER_COOKIE_REFRESH_EACH_REQUEST'):
            request.session[AUTH_USER_REMEMBER] = 'set'

        if AUTH_USER_REMEMBER in request.session:
            operation = request.session.pop(AUTH_USER_REMEMBER, None)

            if operation == 'set' and AUTH_USER_ID in request.session:
                self._set_cookie(request, response)
            elif operation == 'clear':
                self._clear_cookie(response)

        return response

    def _set_cookie(self, request, response):
        # cookie settings
        config = self.app.config
        cookie_name = config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
        domain = config.get('REMEMBER_COOKIE_DOMAIN')
        path = config.get('REMEMBER_COOKIE_PATH', '/')

        secure = config.get('REMEMBER_COOKIE_SECURE', COOKIE_SECURE)
        httponly = config.get('REMEMBER_COOKIE_HTTPONLY', COOKIE_HTTPONLY)

        if 'remember_seconds' in request.session:
            duration = timedelta(seconds=request.session['remember_seconds'])
        else:
            duration = config.get('REMEMBER_COOKIE_DURATION', COOKIE_DURATION)

        # prepare data
        data = encode_cookie(str(request.session[AUTH_USER_ID]))

        if isinstance(duration, int):
            duration = timedelta(seconds=duration)

        try:
            expires = datetime.utcnow() + duration
        except TypeError:
            raise Exception('REMEMBER_COOKIE_DURATION must be a ' +
                            'datetime.timedelta, instead got: {0}'.format(
                                duration))

        # actually set it
        response.set_cookie(cookie_name,
                            value=data,
                            expires=expires,
                            domain=domain,
                            path=path,
                            secure=secure,
                            httponly=httponly)

    def _clear_cookie(self, response):
        config = self.app.config
        cookie_name = config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
        domain = config.get('REMEMBER_COOKIE_DOMAIN')
        path = config.get('REMEMBER_COOKIE_PATH', '/')
        response.delete_cookie(cookie_name, domain=domain, path=path)

    @property
    def _login_disabled(self):
        if self.app:
            return self.app.config.get('LOGIN_DISABLED', False)
        return False

    @_login_disabled.setter
    def _login_disabled(self, value):
        self.app.config['LOGIN_DISABLED'] = value

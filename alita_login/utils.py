# -*- coding: utf-8 -*-
import hmac
import hashlib
import functools
from .config import *
from .security import safe_str_cmp
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
from .signals import user_logged_in, user_logged_out, user_login_confirmed


def encode_cookie(payload, key=None):
    '''
    This will encode a ``unicode`` value into a cookie, and sign that cookie
    with the app's secret key.

    :param payload: The value to encode, as `unicode`.
    :type payload: unicode

    :param key: The key to use when creating the cookie digest. If not
                specified, the SECRET_KEY value from app config will be used.
    :type key: str
    '''
    return u'{0}|{1}'.format(payload, _cookie_digest(payload, key=key))


def decode_cookie(cookie, key=None):
    '''
    This decodes a cookie given by `encode_cookie`. If verification of the
    cookie fails, ``None`` will be implicitly returned.

    :param cookie: An encoded cookie.
    :type cookie: str

    :param key: The key to use when creating the cookie digest. If not
                specified, the SECRET_KEY value from app config will be used.
    :type key: str
    '''
    try:
        payload, digest = cookie.rsplit(u'|', 1)
        if hasattr(digest, 'decode'):
            digest = digest.decode('ascii')  # pragma: no cover
    except ValueError:
        return

    if safe_str_cmp(_cookie_digest(payload, key=key), digest):
        return payload


def make_next_param(login_url, current_url):
    '''
    Reduces the scheme and host from a given URL so it can be passed to
    the given `login` URL more efficiently.

    :param login_url: The login URL being redirected to.
    :type login_url: str
    :param current_url: The URL to reduce.
    :type current_url: str
    '''
    l = urlparse(login_url)
    c = urlparse(current_url)

    if (not l.scheme or l.scheme == c.scheme) and \
            (not l.netloc or l.netloc == c.netloc):
        return urlunparse(('', '', c.path, c.params, c.query, ''))
    return current_url


def expand_login_view(app, login_view):
    '''
    Returns the url for the login view, expanding the view name to a url if
    needed.

    :param login_view: The name of the login view or a URL for the login view.
    :type login_view: str
    '''
    if login_view.startswith(('https://', 'http://', '/')):
        return login_view
    else:
        return app.url_for(login_view)


def login_url(app, login_view, next_url=None, next_field='next'):
    '''
    Creates a URL for redirecting to a login page. If only `login_view` is
    provided, this will just return the URL for it. If `next_url` is provided,
    however, this will append a ``next=URL`` parameter to the query string
    so that the login view can redirect back to that URL. Alita-Login's default
    unauthorized handler uses this function when redirecting to your login url.
    To force the host name used, set `FORCE_HOST_FOR_REDIRECTS` to a host. This
    prevents from redirecting to external sites if request headers Host or
    X-Forwarded-For are present.

    :param login_view: The name of the login view. (Alternately, the actual
                       URL to the login view.)
    :type login_view: str
    :param next_url: The URL to give the login view for redirection.
    :type next_url: str
    :param next_field: What field to store the next URL in. (It defaults to
                       ``next``.)
    :type next_field: str
    '''
    base = expand_login_view(app, login_view)

    if next_url is None:
        return base

    parsed_result = urlparse(base)
    md = parse_qs(parsed_result.query)
    md[next_field] = make_next_param(base, next_url)
    netloc = app.config.get('FORCE_HOST_FOR_REDIRECTS') or \
        parsed_result.netloc
    parsed_result = parsed_result._replace(netloc=netloc, query=urlencode(md))
    return urlunparse(parsed_result)


def login_fresh(request):
    '''
    This returns ``True`` if the current login is fresh.
    '''
    return request.session.get(AUTH_USER_FRESH, False)


async def login_user(request, user, remember=False, duration=None, force=False, fresh=True, expiry_time=None):
    '''
    Logs a user in. You should pass the actual user object to this. If the
    user's `is_active` property is ``False``, they will not be logged in
    unless `force` is ``True``.

    This will return ``True`` if the log in attempt succeeds, and ``False`` if
    it fails (i.e. because the user is inactive).

    :param user: The user object to log in.
    :type user: object
    :param remember: Whether to remember the user after their session expires.
        Defaults to ``False``.
    :type remember: bool
    :param duration: The amount of time before the remember cookie expires. If
        ``None`` the value set in the settings is used. Defaults to ``None``.
    :type duration: :class:`datetime.timedelta`
    :param force: If the user is inactive, setting this to ``True`` will log
        them in regardless. Defaults to ``False``.
    :type force: bool
    :param fresh: setting this to ``False`` will log in the user with a session
        marked as not "fresh". Defaults to ``True``.
    :type fresh: bool
    '''
    if not force and not user.is_active:
        return False

    user_id = getattr(user, request.app.login_manager.id_attribute)()
    request.session[AUTH_USER_ID] = user_id
    request.session[AUTH_USER_FRESH] = fresh
    request.session[AUTH_ID] = request.app.login_manager._session_identifier_generator(request)
    expiry_time = expiry_time or request.app.config.get('LOGIN_EXPIRE_TIME', LOGIN_EXPIRE_TIME)
    request.session.set_expiry(expiry_time)
    await request.session_manager.cycle_session(request.session)

    if remember:
        request.session[AUTH_USER_REMEMBER] = 'set'
        if duration is not None:
            try:
                # equal to timedelta.total_seconds() but works with Python 2.6
                request.session['remember_seconds'] = (duration.microseconds +
                                               (duration.seconds +
                                                duration.days * 24 * 3600) *
                                               10**6) / 10.0**6
            except AttributeError:
                raise Exception('duration must be a datetime.timedelta, '
                                'instead got: {0}'.format(duration))

    request.app.login_manager._update_request_context_with_user(request, user)
    user_logged_in.send(request.app, user=user)
    return True


def logout_user(request):
    '''
    Logs a user out. (You do not need to pass the actual user.) This will
    also clean up the remember me cookie if it exists.
    '''
    if AUTH_USER_ID in request.session:
        request.session.pop(AUTH_USER_ID)

    if AUTH_USER_FRESH in request.session:
        request.session.pop(AUTH_USER_FRESH)

    if AUTH_ID in request.session:
        request.session.pop(AUTH_ID)

    cookie_name = request.app.config.get('REMEMBER_COOKIE_NAME', COOKIE_NAME)
    if cookie_name in request.cookies:
        request.session[AUTH_USER_REMEMBER] = 'clear'
        if 'remember_seconds' in request.session:
            request.session.pop('remember_seconds')
    user_logged_out.send(request.app, user=request.user)
    return True


def confirm_login(request):
    '''
    This sets the current session as fresh. Sessions become stale when they
    are reloaded from a cookie.
    '''
    request.session[AUTH_USER_FRESH] = True
    request.session[AUTH_ID] = request.app.login_manager._session_identifier_generator()
    user_login_confirmed.send(request.app)


def login_required(func):
    '''
    If you decorate a view with this, it will ensure that the current user is
    logged in and authenticated before calling the actual view. (If they are
    not, it calls the :attr:`LoginManager.unauthorized` callback.) For
    example::

        @app.route('/post')
        @login_required
        def post():
            pass

    If there are only certain times you need to require that your user is
    logged in, you can do so with::

        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()

    ...which is essentially the code that this function adds to your views.

    It can be convenient to globally turn off authentication when unit testing.
    To enable this, if the application configuration variable `LOGIN_DISABLED`
    is set to `True`, this decorator will be ignored.

    .. Note ::

        Per `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        HTTP ``OPTIONS`` requests are exempt from login checks.

    :param func: The view function to decorate.
    :type func: function
    '''
    @functools.wraps(func)
    async def decorated_view(*args, **kwargs):
        request = args[0]
        if request.method in EXEMPT_METHODS:
            return await func(*args, **kwargs)
        elif request.app.config.get('LOGIN_DISABLED'):
            return await func(*args, **kwargs)
        elif not request.user.is_authenticated:
            return request.app.login_manager.unauthorized(request)
        return await func(*args, **kwargs)
    return decorated_view


def fresh_login_required(func):
    '''
    If you decorate a view with this, it will ensure that the current user's
    login is fresh - i.e. their session was not restored from a 'remember me'
    cookie. Sensitive operations, like changing a password or e-mail, should
    be protected with this, to impede the efforts of cookie thieves.

    If the user is not authenticated, :meth:`LoginManager.unauthorized` is
    called as normal. If they are authenticated, but their session is not
    fresh, it will call :meth:`LoginManager.needs_refresh` instead. (In that
    case, you will need to provide a :attr:`LoginManager.refresh_view`.)

    Behaves identically to the :func:`login_required` decorator with respect
    to configutation variables.

    .. Note ::

        Per `W3 guidelines for CORS preflight requests
        <http://www.w3.org/TR/cors/#cross-origin-request-with-preflight-0>`_,
        HTTP ``OPTIONS`` requests are exempt from login checks.

    :param func: The view function to decorate.
    :type func: function
    '''
    @functools.wraps(func)
    def decorated_view(*args, **kwargs):
        request = args[0]
        if request.method in EXEMPT_METHODS:
            return func(*args, **kwargs)
        elif request.app.config.get('LOGIN_DISABLED'):
            return func(*args, **kwargs)
        elif not request.user.is_authenticated:
            return request.app.login_manager.unauthorized(request)
        elif not login_fresh(request):
            return request.app.login_manager.needs_refresh(request)
        return func(*args, **kwargs)
    return decorated_view


def set_login_view(app, login_view, blueprint=None):
    '''
    Sets the login view for the app or blueprint. If a blueprint is passed,
    the login view is set for this blueprint on ``blueprint_login_views``.

    :param login_view: The user object to log in.
    :type login_view: str
    :param blueprint: The blueprint which this login view should be set on.
        Defaults to ``None``.
    :type blueprint: object
    '''

    num_login_views = len(app.login_manager.blueprint_login_views)
    if blueprint is not None or num_login_views != 0:

        (app.login_manager
            .blueprint_login_views[blueprint.name]) = login_view

        if (app.login_manager.login_view is not None and
                None not in app.login_manager.blueprint_login_views):

            app.login_manager.blueprint_login_views[None] = app.login_manager.login_view

        app.login_manager.login_view = None
    else:
        app.login_manager.login_view = login_view


def _get_user(request):
    if not hasattr(request, 'user'):
        request.app.login_manager._load_user(request)
    return getattr(request, 'user', None)


def _cookie_digest(payload, key=None):
    key = _secret_key(key)

    return hmac.new(key, payload.encode('utf-8'), hashlib.sha512).hexdigest()


def _get_remote_addr(request):
    address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if address is not None:
        # An 'X-Forwarded-For' header includes a comma separated list of the
        # addresses, the first address being the actual remote address.
        address = address.encode('utf-8').split(b',')[0].strip()
    return address


def _create_identifier(request):
    user_agent = request.headers.get('User-Agent')
    if user_agent is not None:
        user_agent = user_agent.encode('utf-8')
    base = '{0}|{1}'.format(_get_remote_addr(request), user_agent)
    if str is bytes:
        base = str(base, 'utf-8', errors='replace')  # pragma: no cover
    h = hashlib.sha512()
    h.update(base.encode('utf8'))
    return h.hexdigest()


async def _user_context_processor(request):
    return dict(current_user=_get_user(request))


def _secret_key(app, key=None):
    if key is None:
        key = app.config['SECRET_KEY']

    if isinstance(key, str):  # pragma: no cover
        key = key.encode('latin1')  # ensure bytes

    return key

# -*- coding: utf-8 -*-
from .config import *
from .manager import LoginManager
from .mixins import UserMixin, AnonymousUserMixin
from .signals import (user_logged_in, user_logged_out, user_loaded_from_cookie,
                      user_loaded_from_header, user_loaded_from_request,
                      user_login_confirmed, user_unauthorized,
                      user_needs_refresh, user_accessed, session_protected)
from .utils import (login_url, login_fresh, login_user,
                    logout_user, confirm_login, login_required,
                    fresh_login_required, set_login_view, encode_cookie,
                    decode_cookie, make_next_param)

__version__ = '0.1.0'


__all__ = [
    LoginManager.__name__,
    UserMixin.__name__,
    AnonymousUserMixin.__name__,
    __version__,
    'COOKIE_NAME',
    'COOKIE_DURATION',
    'COOKIE_SECURE',
    'COOKIE_HTTPONLY',
    'LOGIN_MESSAGE',
    'LOGIN_MESSAGE_CATEGORY',
    'REFRESH_MESSAGE',
    'REFRESH_MESSAGE_CATEGORY',
    'ID_ATTRIBUTE',
    'AUTH_HEADER_NAME',
    'user_logged_in',
    'user_logged_out',
    'user_loaded_from_cookie',
    'user_loaded_from_header',
    'user_loaded_from_request',
    'user_login_confirmed',
    'user_unauthorized',
    'user_needs_refresh',
    'user_accessed',
    'session_protected',
    'login_url',
    'login_fresh',
    'login_user',
    'logout_user',
    'confirm_login',
    'login_required',
    'fresh_login_required',
    'set_login_view',
    'encode_cookie',
    'decode_cookie',
    'make_next_param',
]

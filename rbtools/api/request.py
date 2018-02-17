from __future__ import unicode_literals

import base64
import logging
import mimetypes
import os
import random
import shutil
import sys
from itertools import chain
from json import loads as json_loads

import six
from six.moves.http_client import UNAUTHORIZED, NOT_MODIFIED
from six.moves.http_cookiejar import Cookie, CookieJar, MozillaCookieJar
from six.moves.urllib.error import HTTPError, URLError
from six.moves.urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from six.moves.urllib.request import (
    BaseHandler,
    HTTPBasicAuthHandler,
    HTTPCookieProcessor,
    HTTPDigestAuthHandler,
    HTTPErrorProcessor,
    HTTPPasswordMgr,
    ProxyHandler,
    Request as URLRequest,
    build_opener,
    install_opener,
    urlopen)

from rbtools import get_package_version
from rbtools.api.cache import APICache
from rbtools.api.errors import APIError, create_api_error, ServerInterfaceError
from rbtools.utils.filesystem import get_home_path


# Python 2.7.9+ added strict HTTPS certificate validation (finally). These APIs
# don't exist everywhere so soft-import them.
try:
    import ssl
    from six.moves.urllib.request import HTTPSHandler
except ImportError:
    ssl = None
    HTTPSHandler = None


RBTOOLS_COOKIE_FILE = '.rbtools-cookies'
RB_COOKIE_NAME = 'rbsessionid'


class HttpRequest(object):
    """High-level HTTP-request object."""
    def __init__(self, url, method='GET', query_args={}):
        self.method = method
        self.headers = {}
        self._fields = {}
        self._files = {}

        # Replace all underscores in each query argument
        # key with dashes.
        query_args = dict([
            (key.replace('_', '-'), value)
            for key, value in six.iteritems(query_args)
        ])

        # Add the query arguments to the url
        url_parts = list(urlparse(url))
        query = dict(parse_qsl(url_parts[4]))
        query.update(query_args)
        url_parts[4] = urlencode(query)
        self.url = urlunparse(url_parts)

    def add_field(self, name, value):
        self._fields[name] = value

    def add_file(self, name, filename, content):
        self._files[name] = {
            'filename': filename,
            'content': content,
        }

    def del_field(self, name):
        del self._fields[name]

    def del_file(self, filename):
        del self._files[filename]

    def encode_multipart_formdata(self):
        """Encodes data for use in an HTTP request.

        Parameters:
            fields - the fields to be encoded.  This should be a dict in a
                     key:value format
            files  - the files to be encoded.  This should be a dict in a
                     key:dict, filename:value and content:value format
        """
        NEWLINE = b'\r\n'
        # This must be the same for all parts of this block
        boundary_value = self._make_mime_boundary()
        DASH_BOUNDARY = b'-' * 2 + boundary_value
        CLOSE_BOUNDARY = NEWLINE + DASH_BOUNDARY + b'-' * 2

        def binary_encode(value):
            if not isinstance(value, six.binary_type):
                # Works for numbers and Unicode
                value = six.text_type(value).encode('utf-8')
            return value

        def multipart_body(name, body_part, filename=None):
            """
            if filename is set then we expect mimetype to also be set
            # Format of Internet Message Bodies
            https://www.ietf.org/rfc/rfc2045.txt
            # Media Types
            https://tools.ietf.org/html/rfc2046#section-5.1
            # Content-Disposition
            https://tools.ietf.org/html/rfc2183#section-2.3
            # multipart/form-data
            https://tools.ietf.org/html/rfc7578#page-4
            """
            encapsulation = NEWLINE + DASH_BOUNDARY + NEWLINE
            encapsulation += b'Content-Disposition: '
            # name should only be 7-bit ascii
            encapsulation += b'form-data ; name="%s"; ' % binary_encode(name)
            if filename:
                encapsulation += b'; filename=%s' % binary_encode(filename)
                mime_type, encoding = mimetypes.guess_type(filename)
                if not mime_type:
                    mime_type = b'application/octet-stream'

                # Without this it is assumed to be US-ASCII
                encapsulation += (NEWLINE + b'Content-Type: %s' %
                                  binary_encode(mime_type))

            encapsulation += NEWLINE * 2 + binary_encode(body_part)

            # End with a second NEWLINE
            return encapsulation

        if not (self._fields or self._files):
            return None, None

        content_type = b'multipart/form-data; boundary=%s' % boundary_value
        content = six.BytesIO()

        for name, value in chain(self._fields.items(), self._files.items()):
            filename = None
            data = value
            if isinstance(value, dict):
                if 'filename' in value:
                    filename = value['filename']
                if 'content' in value:
                    data = value['content']

            content.write(multipart_body(name, data, filename))
        content.write(CLOSE_BOUNDARY)
        return content_type, content.getvalue()

    def _make_mime_boundary(self):
        """Create a mime boundary.

        This exists because mimetools.choose_boundary() is gone in Python 3.x,
        and email.generator._make_boundary isn't really appropriate to use
        here.
        """
        fmt = '%%0%dd' % len(repr(sys.maxsize - 1))
        token = random.randrange(sys.maxsize)
        boundary = '=' * 15 + fmt % token + '=='
        return boundary.encode()


class Request(URLRequest):
    """A request which contains a method attribute."""
    def __init__(self, url, body='', headers={}, method='PUT'):
        URLRequest.__init__(self, url, body, headers)
        self.method = method

    def get_method(self):
        return self.method


class PresetHTTPAuthHandler(BaseHandler):
    """Handler that presets the use of HTTP Basic Auth."""
    handler_order = 480  # After Basic auth

    AUTH_HEADER = 'Authorization'

    def __init__(self, url, password_mgr):
        self.url = url
        self.password_mgr = password_mgr
        self.used = False

    def reset(self, username, password):
        self.password_mgr.rb_user = username
        self.password_mgr.rb_pass = password
        self.used = False

    def http_request(self, request):
        if not self.used:
            if self.password_mgr.api_token:
                request.add_header(self.AUTH_HEADER,
                                   'token %s' % self.password_mgr.api_token)
                self.used = True
            elif self.password_mgr.rb_user:
                # Note that we call password_mgr.find_user_password to get the
                # username and password we're working with.
                username, password = \
                    self.password_mgr.find_user_password('Web API', self.url)
                raw = '{}:{}'.format(username, password).encode()
                request.add_header(self.AUTH_HEADER, 'Basic ' +
                                   base64.b64encode(raw).decode('ascii'))
                self.used = True

        return request

    https_request = http_request


class ReviewBoardHTTPErrorProcessor(HTTPErrorProcessor):
    """Processes HTTP error codes."""
    def http_response(self, request, response):
        if response.code == NOT_MODIFIED:
            return response
        return super(ReviewBoardHTTPErrorProcessor, self).http_response(
            request, response)

    https_response = http_response


class ReviewBoardHTTPBasicAuthHandler(HTTPBasicAuthHandler):
    """Custom Basic Auth handler that doesn't retry excessively.

    urllib's HTTPBasicAuthHandler retries over and over, which is useless. This
    subclass only retries once to make sure we've attempted with a valid
    username and password. It will then fail so we can use our own retry
    handler.

    This also supports two-factor auth, for Review Board servers that
    support it. When requested by the server, the client will be prompted
    for a one-time password token, which would be sent generally through
    a mobile device. In this case, the client will prompt up to a set
    number of times until a valid token is entered.
    """
    OTP_TOKEN_HEADER = 'X-ReviewBoard-OTP'
    MAX_OTP_TOKEN_ATTEMPTS = 5

    def __init__(self, *args, **kwargs):
        HTTPBasicAuthHandler.__init__(self, *args, **kwargs)
        self._retried = False
        self._lasturl = ""
        self._needs_otp_token = False
        self._otp_token_attempts = 0

    def retry_http_basic_auth(self, host, request, realm, *args, **kwargs):
        if self._lasturl != host:
            self._retried = False

        self._lasturl = host

        if self._retried:
            return None

        self._retried = True

        response = self._do_http_basic_auth(host, request, realm)

        if response and response.code != UNAUTHORIZED:
            self._retried = False

        return response

    def _do_http_basic_auth(self, host, request, realm):
        user, password = self.passwd.find_user_password(realm, host)

        if password is None:
            return None

        raw = '{}:{}'.format(user, password).encode()
        auth = 'Basic ' + base64.b64encode(raw).decode('ascii')

        if (request.headers.get(self.auth_header, None) == auth and
            (not self._needs_otp_token or
             self._otp_token_attempts > self.MAX_OTP_TOKEN_ATTEMPTS)):
            # We've already tried with these credentials. No point
            # trying again.
            return None

        request.add_unredirected_header(self.auth_header, auth.decode('utf-8'))

        try:
            response = self.parent.open(request, timeout=request.timeout)
            return response
        except HTTPError as e:
            if e.code == UNAUTHORIZED:
                headers = e.info()
                otp_header = headers.get(self.OTP_TOKEN_HEADER, '')

                if otp_header.startswith('required'):
                    self._needs_otp_token = True

                    # The server has requested a one-time password token, sent
                    # through an external channel (cell phone or application).
                    # Request this token from the user.
                    required, token_method = otp_header.split(';')

                    token = self.passwd.get_otp_token(request.get_full_url(),
                                                      token_method.strip())

                    if not token:
                        return None

                    request.add_unredirected_header(self.OTP_TOKEN_HEADER,
                                                    token)
                    self._otp_token_attempts += 1

                    return self._do_http_basic_auth(host, request, realm)

            raise

        return None


class ReviewBoardHTTPPasswordMgr(HTTPPasswordMgr):
    """Adds HTTP authentication support for URLs.

    Python 2.4's password manager has a bug in http authentication
    when the target server uses a non-standard port.  This works
    around that bug on Python 2.4 installs.

    See: http://bugs.python.org/issue974757
    """
    def __init__(self, reviewboard_url, rb_user=None, rb_pass=None,
                 api_token=None, auth_callback=None, otp_token_callback=None):
        HTTPPasswordMgr.__init__(self)
        self.passwd = {}
        self.rb_url = reviewboard_url
        self.rb_user = rb_user
        self.rb_pass = rb_pass
        self.api_token = api_token
        self.auth_callback = auth_callback
        self.otp_token_callback = otp_token_callback

    def find_user_password(self, realm, uri):
        if realm == 'Web API':
            if self.auth_callback:
                username, password = self.auth_callback(realm, uri,
                                                        username=self.rb_user,
                                                        password=self.rb_pass)
                self.rb_user = username
                self.rb_pass = password

            return self.rb_user, self.rb_pass
        else:
            # If this is an auth request for some other domain (since HTTP
            # handlers are global), fall back to standard password management.
            return HTTPPasswordMgr.find_user_password(self, realm, uri)

    def get_otp_token(self, uri, method):
        if self.otp_token_callback:
            return self.otp_token_callback(uri, method)


def create_cookie_jar(cookie_file=None):
    """Return a cookie jar backed by cookie_file

    If cooie_file is not provided, we will default it. If the
    cookie_file does not exist, we will create it with the proper
    permissions.

    In the case where we default cookie_file, and it does not exist,
    we will attempt to copy the .post-review-cookies.txt file.
    """
    home_path = get_home_path()

    if not cookie_file:
        cookie_file = os.path.join(home_path, RBTOOLS_COOKIE_FILE)
        post_review_cookies = os.path.join(home_path,
                                           '.post-review-cookies.txt')

        if (not os.path.isfile(cookie_file) and
            os.path.isfile(post_review_cookies)):
            try:
                shutil.copyfile(post_review_cookies, cookie_file)
                os.chmod(cookie_file, 0o600)
            except IOError as e:
                logging.warning("There was an error while copying "
                                "post-review's cookies: %s", e)

    if not os.path.isfile(cookie_file):
        try:
            open(cookie_file, 'w').close()
            os.chmod(cookie_file, 0o600)
        except IOError as e:
            logging.warning('There was an error while creating a '
                            'cookie file: %s', e)

    return MozillaCookieJar(cookie_file), cookie_file


class ReviewBoardServer(object):
    """Represents a Review Board server we are communicating with.

    Provides methods for executing HTTP requests on a Review Board
    server's Web API.

    The ``auth_callback`` parameter can be used to specify a callable
    which will be called when authentication fails. This callable will
    be passed the realm, and url of the Review Board server and should
    return a 2-tuple of username, password. The user can be prompted
    for their credentials using this mechanism.
    """
    def __init__(self, url, cookie_file=None, username=None, password=None,
                 api_token=None, agent=None, session=None, disable_proxy=False,
                 auth_callback=None, otp_token_callback=None,
                 verify_ssl=True, save_cookies=True, ext_auth_cookies=None):
        if not url.endswith('/'):
            url += '/'

        self.url = url + 'api/'

        self.save_cookies = save_cookies
        self.ext_auth_cookies = ext_auth_cookies

        if self.save_cookies:
            self.cookie_jar, self.cookie_file = create_cookie_jar(
                cookie_file=cookie_file)

            try:
                self.cookie_jar.load(ignore_expires=True)
            except IOError:
                pass
        else:
            self.cookie_jar = CookieJar()
            self.cookie_file = None

        if self.ext_auth_cookies:
            try:
                self.cookie_jar.load(ext_auth_cookies, ignore_expires=True)
            except IOError as e:
                logging.critical('There was an error while loading a '
                                 'cookie file: %s', e)
                pass

        # Get the cookie domain from the url. If the domain
        # does not contain a '.' (e.g. 'localhost'), we assume
        # it is a local domain and suffix it (See RFC 2109).
        parsed_url = urlparse(url)
        self.domain = parsed_url[1].partition(':')[0]  # Remove Port.

        if self.domain.count('.') < 1:
            self.domain = '%s.local' % self.domain

        if session:
            cookie = Cookie(
                version=0,
                name=RB_COOKIE_NAME,
                value=session,
                port=None,
                port_specified=False,
                domain=self.domain,
                domain_specified=True,
                domain_initial_dot=True,
                path=parsed_url[2],
                path_specified=True,
                secure=False,
                expires=None,
                discard=False,
                comment=None,
                comment_url=None,
                rest={'HttpOnly': None})
            self.cookie_jar.set_cookie(cookie)

            if self.save_cookies:
                self.cookie_jar.save()

        if username:
            # If the username parameter is given, we have to clear the session
            # cookie manually or it will override the username:password
            # combination retrieved from the authentication callback.
            try:
                self.cookie_jar.clear(self.domain, parsed_url[2],
                                      RB_COOKIE_NAME)
            except KeyError:
                pass

        # Set up the HTTP libraries to support all of the features we need.
        password_mgr = ReviewBoardHTTPPasswordMgr(self.url,
                                                  username,
                                                  password,
                                                  api_token,
                                                  auth_callback,
                                                  otp_token_callback)
        self.preset_auth_handler = PresetHTTPAuthHandler(self.url,
                                                         password_mgr)

        handlers = []

        if not verify_ssl:
            context = ssl._create_unverified_context()
            handlers.append(HTTPSHandler(context=context))

        if disable_proxy:
            handlers.append(ProxyHandler({}))

        handlers += [
            HTTPCookieProcessor(self.cookie_jar),
            ReviewBoardHTTPBasicAuthHandler(password_mgr),
            HTTPDigestAuthHandler(password_mgr),
            self.preset_auth_handler,
            ReviewBoardHTTPErrorProcessor(),
        ]

        if agent:
            self.agent = agent
        else:
            self.agent = 'RBTools/' + get_package_version()

        opener = build_opener(*handlers)
        opener.addheaders = [
            ('User-agent', self.agent),
        ]
        install_opener(opener)

        self._cache = None
        self._urlopen = urlopen

    def enable_cache(self, cache_location=None, in_memory=False):
        """Enable caching for all future HTTP requests.

        The cache will be created at the default location if none is provided.

        If the in_memory parameter is True, the cache will be created in memory
        instead of on disk. This overrides the cache_location parameter.
        """
        if not self._cache:
            self._cache = APICache(create_db_in_memory=in_memory,
                                   db_location=cache_location)

            self._urlopen = self._cache.make_request

    def login(self, username, password):
        """Reset the user information"""
        self.preset_auth_handler.reset(username, password)

    def logout(self):
        """Logs the user out of the session."""
        self.preset_auth_handler.reset(None, None)
        self.make_request(HttpRequest('%ssession/' % self.url,
                                      method='DELETE'))
        self.cookie_jar.clear(self.domain)

        if self.save_cookies:
            self.cookie_jar.save()

    def process_error(self, http_status, data):
        """Processes an error, raising an APIError with the information."""
        try:
            rsp = json_loads(data)

            assert rsp['stat'] == 'fail'

            logging.debug('Got API Error %d (HTTP code %d): %s',
                          rsp['err']['code'], http_status, rsp['err']['msg'])
            logging.debug('Error data: %r', rsp)

            raise create_api_error(http_status, rsp['err']['code'], rsp,
                                   rsp['err']['msg'])
        except ValueError:
            logging.debug('Got HTTP error: %s: %s', http_status, data)
            raise APIError(http_status, None, None, data)

    def make_request(self, request):
        """Perform an http request.

        The request argument should be an instance of
        'rbtools.api.request.HttpRequest'.
        """
        try:
            content_type, body = request.encode_multipart_formdata()
            headers = request.headers

            if body:
                headers.update({
                    'Content-Type': content_type,
                    'Content-Length': len(body),
                })
            else:
                headers['Content-Length'] = '0'

            rsp = self._urlopen(Request(
                request.url, body, headers, request.method))
        except HTTPError as e:
            self.process_error(e.code, e.read())
        except URLError as e:
            raise ServerInterfaceError('%s' % e.reason)

        if self.save_cookies:
            try:
                self.cookie_jar.save()
            except IOError:
                pass

        return rsp

# Copyright 2017 NOKIA
# All Rights Reserved.

from future.utils import lrange

import base64
import json
import logging
import socket
import ssl
import time

try:
    import httplib as httpclient      # python 2
except ImportError:
    import http.client as httpclient  # python 3

LOG = logging.getLogger(__name__)
MAX_RETRIES = 5

REST_SERV_UNAVAILABLE_CODE = 503


class RESTResponse(object):
    def __init__(self, status_code, reason=None, data=None, headers=None):
        """Initializes a request """

        self.status = status_code
        self.data = data
        self.reason = reason
        self.headers = headers


class RESTProxyBaseException(Exception):
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        try:
            super(RESTProxyBaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            if self.use_fatal_exceptions():
                raise
            else:
                super(RESTProxyBaseException, self).__init__(self.message)

    def __unicode__(self):
        return str(self.msg)

    def use_fatal_exceptions(self):
        return False


class RESTProxyError(RESTProxyBaseException):
    def __init__(self, message, error_code=None):
        self.code = 0
        if error_code:
            self.code = error_code

        if message is None:
            message = "None"

        if self.code == 409:
            self.message = (message)
        else:
            self.message = (("Error in REST call to VSD: %s") % message)
        super(RESTProxyError, self).__init__()


class RESTProxyServer(object):
    def __init__(self, server, base_uri, serverssl,
                 serverauth, auth_resource,
                 organization, servertimeout):
        try:
            server_ip, port = server.split(":")
        except ValueError:
            server_ip = server
            port = None
        self.server = server_ip
        self.port = port if port else None
        self.base_uri = base_uri
        self.serverssl = serverssl
        self.serverauth = serverauth
        self.auth_resource = auth_resource
        self.organization = organization
        self.timeout = servertimeout
        self.max_retries = MAX_RETRIES
        self.auth = None
        self.success_codes = lrange(200, 207)

    def _rest_call(self, action, resource, data, extra_headers=None):
        uri = self.base_uri + resource
        body = json.dumps(data)
        headers = {'Content-type': 'application/json',
                   'X-Nuage-Organization': self.organization}
        if self.auth:
            headers['Authorization'] = self.auth
        if extra_headers:
            headers.update(extra_headers)

        if "X-Nuage-Filter" in headers:
            hdr = '[' + headers['X-Nuage-Filter'] + ']'
            LOG.debug('API REQ %s %s %s %s', action, uri, hdr, body)
        else:
            LOG.debug('API REQ %s %s %s', action, uri, body)

        ret = None
        for attempt in range(self.max_retries):
            conn = None
            try:
                conn = self._create_connection()
                conn.request(action, uri, body, headers)
                response = conn.getresponse()
                resp_str = response.read()
                resp_data = resp_str

                LOG.debug('API RSP %s %s %s',
                          response.status,
                          response.reason,
                          resp_data)
                if response.status in self.success_codes:
                    try:
                        resp_data = json.loads(resp_str.decode('utf8'))
                    except ValueError:
                        # response was not JSON, ignore the exception
                        pass

                ret = RESTResponse(status_code=response.status,
                                   reason=response.reason,
                                   data=resp_data,
                                   headers=dict(response.getheaders()))

            except (socket.timeout, socket.error) as e:  # noqa
                LOG.error(('ServerProxy: %(action)s failure, %(e)r'),
                          locals())
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
            else:
                # no exception received or got exception != above ones
                conn.close()
                if response.status != REST_SERV_UNAVAILABLE_CODE:
                    return ret

            time.sleep(1)
            LOG.debug('Attempt %s of %s' % (attempt + 1, self.max_retries))

        LOG.debug('After %d retries server did not respond properly.'
                  % self.max_retries)
        return ret or None

    @staticmethod
    def raise_rest_error(msg, exc=None, log_as_error=True):
        if log_as_error:
            LOG.error(('RESTProxy: %s'), msg)
        else:
            LOG.debug(('RESTProxy: %s'), msg)
        if exc:
            raise exc
        else:
            raise Exception(msg)

    def _create_connection(self):
        if self.serverssl:
            if hasattr(ssl, '_create_unverified_context'):
                # pylint: disable=no-member
                # pylint: disable=unexpected-keyword-arg
                conn = httpclient.HTTPSConnection(
                    self.server, self.port, timeout=self.timeout,
                    context=ssl._create_unverified_context())
                # pylint: enable=no-member
                # pylint: enable=unexpected-keyword-arg
            else:
                conn = httpclient.HTTPSConnection(
                    self.server, self.port, timeout=self.timeout)
        else:
            conn = httpclient.HTTPConnection(
                self.server, self.port, timeout=self.timeout)

        if conn is None:
            self.raise_rest_error(
                'Could not create HTTP(S)Connection object.')
        return conn

    def generate_nuage_auth(self):
        data = ''
        encoded_auth = base64.b64encode(
            self.serverauth.encode()).decode()
        self.auth = 'Basic ' + encoded_auth
        resp = self.rest_call('GET',
                              self.auth_resource, data)
        data = resp.data[0]
        if resp.status in self.success_codes and data['APIKey']:
            respkey = data['APIKey']
        else:
            if resp.status == 0:
                assert 0, 'Could not establish conn with REST server. Abort'
            else:
                assert 0, 'Could not authenticate to REST server. Abort'
        uname = self.serverauth.split(':')[0]
        new_uname_pass = uname + ':' + respkey
        encoded_auth = base64.b64encode(new_uname_pass.encode()).decode()
        auth = 'Basic ' + encoded_auth
        self.auth = auth

    def rest_call(self, action, resource, data, extra_headers=None):
        response = self._rest_call(action, resource, data,
                                   extra_headers=extra_headers)
        '''
        If at all authentication expires with VSD, re-authenticate.
        '''
        if response.status == 401 and response.reason == 'Unauthorized':
            self.generate_nuage_auth()
            return self._rest_call(action, resource, data,
                                   extra_headers=extra_headers)
        return response

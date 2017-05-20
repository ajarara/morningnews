import json
import requests
from hashlib import md5, sha1

from contextlib import contextmanager

# this is more or less arbitrary, but it will effect the way it's represented in the UI
DEVICE = 'MediaBrowser Client="Emby Mobile", Device="Firefox", DeviceId="27d9f5adc15f875265f6aeb29062218d7a58c717", Version="3.2.10.0"'

EMBY_IP = '192.168.5.151:8096'

PROTO = 'http://'

EMBY_URL = PROTO + EMBY_IP


class EmbyController():

    def __init__(self, username, password, emby_ip=EMBY_IP):
        self.username = username
        self.password = password.encode('utf-8')  # for hashlib
        self.emby_ip = emby_ip
        self.emby_url = PROTO + emby_ip
        self._api = None

    def _get_api(self, auth=DEVICE):
        ''' Get the full http response from an Auth attempt. A 200
        indicates success, anything else indicates otherwise.'''
        emby_token_url = "{}/emby/Users/authenticatebyname".format(self.emby_url)
        # encoding?
        auth_params = json.dumps(
            {
                'Password': sha1(self.password).hexdigest(),
                'PasswordMd5': md5(self.password).hexdigest(),
                'Username': self.username
            }
        )
        auth_headers = {
            'Content-type': 'application/json',
            'x-emby-authorization': auth,
        }
        resp =  requests.post(
            emby_token_url,
            data = auth_params,
            headers = auth_headers)
        _emby_conn_check(self, resp, "Emby auth failed!")
        return resp

    def _auth_headers(self):
        # do we make posts exclusively with json? should that be here?
        return {
            'Content-type': 'application/json',
            'X-MediaBrowser-Token': self.api()['AccessToken']
        }


    def api(self, _cache={}):
        ''' 
        Return an easily digestible interface to the... interface
        '''
        if not self._api:
            sess = self._get_api()
            self._api = _json_to_dict(sess.content)

        # a interesting sanity check is to see if _cache has different
        # keys inside it than what we expect. If so, throw an exception
        # as the _cache is being overriden by something. This won't
        # catch all cases but it's interesting enough to make note of.

        # if the cache isn't populated, make it so
        if not _cache:
            _cache['UserId'] = self._api['SessionInfo']['UserId']
            _cache['AccessToken'] = self._api['AccessToken']
        return _cache

    def get_library(self):
        emby_lib_url = "{}/emby/Users/{}/Views".format(
            self.emby_url,
            self.api()['UserId']
        )
        conn = requests.get(emby_lib_url, headers=self._auth_headers())
        _emby_conn_check(self, conn, "Emby library retrieve failed!")
        return _json_to_dict(conn.content)

    def get_live_tv(self):
        emby_live_tv = "{}/emby/LiveTv/Channels".format(
            self.emby_url
        )
        conn = requests.get(emby_live_tv, headers=self._auth_headers())
        _emby_conn_check(self, conn, "Emby live tv retrieve failed!")
        return _json_to_dict(conn.content)

    # not sure if this is necessary. It returns a 401 in the web client.
    # def logout(self):
    #     emby_logout_url = "{}/emby/Sessions/Logout".format(self.emby_url)
    #     resp = requests.post(emby_logout_url, headers=self._auth_headers())
    #     _emby_conn_check(self, resp, "Emby logout failed!")
    #     return True


def _json_to_dict(jsonbytes):
    return json.loads(jsonbytes.decode('utf-8'))

def _emby_conn_check(controller, conn, error_msg):
    if conn.status_code != 200:
        raise ValueError('''
        Err: {} 
        Username: {}
        sha1: {}
        md5: {}
        Headers: {}
        Content: {}'''.format(
            error_msg,
            controller.username,
            sha1(controller.password).hexdigest(),
            md5(controller.password).hexdigest(),
            conn.headers,
            conn.content))


import json
import requests
from hashlib import md5, sha1

# ==================== BEGIN GLOBALS ====================
# later on we will parse these as runtime options.

# this is more or less arbitrary, but it will effect the way it's
# represented in the UI
DEVICE = 'MediaBrowser Client="Emby Mobile", Device="Firefox", DeviceId="27d9f5adc15f875265f6aeb29062218d7a58c717", Version="3.2.10.0"'

EMBY_IP = '192.168.5.151:8096'

PROTO = 'http://'

EMBY_URL = PROTO + EMBY_IP

# ==================== END GLOBALS ====================

def sess(_sess=[]):
    if _sess:
        return _sess[0]
    _sess.append(requests.session())
    return _sess[0]
    

def getAuthRespFor(username, password, _cache={}, device=DEVICE):
    ''' EMBY ONLY '''
    password = password.encode('utf-8')
    if (username, password) in _cache:
        return _cache[username, password]
    emby_token_url = "{}/emby/Users/authenticatebyname".format(EMBY_URL)
    auth_params = json.dumps(
        {
            'Password': sha1(password).hexdigest(),
            'PasswordMd5': md5(password).hexdigest(),
            'Username': username
        }
    )
    headers = {
        'Content-type': 'application/json',
        # don't be fooled by this, this is just to tell emby what kind
        # of device you've got. Not important, but mandatory.
        'x-emby-authorization': device
    }
    resp = sess().post(
        emby_token_url,
        data = auth_params,
        headers = headers)
    _emby_conn_check((username, password), resp, "Emby auth failed!")
    _cache[username, password] = resp
    return resp

def _authHeaders(accessToken):
    return {
        'Content-type': 'application/json',
        'X-MediaBrowser-Token': accessToken
        }
    

def get_prop_from_resp(resp, prop):
    # whether or not this should be pushed up
    # is an interesting design choice
    content = resp_to_content_dict(resp)
    # if there's a valueError we want to know about it, so don't catch them.

    # one of the issues is that possibly not all responses have these.
    return {
        'UserId': content['SessionInfo']['UserId'],
        'AccessToken': content['AccessToken']
        }[prop]

def getLiveTv(key, UserId):
    return sess().get(
        "{}/emby/Users/{}/Views".format(
            EMBY_URL,
            UserId),
        headers = _authHeaders(key))



# ====================  CLASS BASED ====================

def resp_to_content_dict(resp):
    return json.loads(resp.content.decode('utf-8'))

def _extract_invariants_from_resp(resp):
    vals = resp_to_content_dict(resp)
    return {
        'UserId': vals['SessionInfo']['UserId'],
        'AccessToken': vals['AccessToken']
    }


class EmbyController():

    def __init__(self, username, password, emby_ip=EMBY_IP,
                 proto=PROTO, device=DEVICE):
        self.username = username
        self.password = password.encode('utf-8')  # for hashlib
        self.emby_ip = emby_ip
        self.device = DEVICE

        self.emby_url = proto + emby_ip
        self.session_state = None

    def get(self, directory, auth=False):
        ''' get a http response from server '''
        if auth:
            resp = requests.get(
                '{}'.format(self.emby_url) + directory,
                headers = self._auth_headers()
            )
        else:
            resp = requests.get(
                '{}'.format(self.emby_url) + directory)
        self._emby_conn_check(resp, "Get request failed!")
        return resp

    def post(self, directory, auth=False):
        ''' post a http form to server, returning reply '''
        if auth:
            resp = requests.post(
                '{}'.format(self.emby_url) + directory,
                headers = self._auth_headers()
                )
        else:
            resp = requests.post(
                '{}'.format(self.emby_url) + directory)
        self._emby_conn_check(resp, "Post request failed!")
        return resp

    def session_invariants(self, key=None):
        ''' 
        Interface to all session invariants, including api
        key. Can be used as a generic interface
        '''
        # we want userid, and api key for now, but want to have the ability
        # to expand on this without breaking the interface.
        # likely a dictionary is best.
        if self.session_state:
            if key:
                return self.session_state[key]
            return self.session_state
        # okay, if at this point it means 
        # we haven't authorized. Let's do so.
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
            'x-emby-authorization': self.device,
        }
        resp =  requests.post(
            emby_token_url,
            data = auth_params,
            headers = auth_headers)
        self._emby_conn_check(resp, "Emby auth failed!")
        self.session_state = _extract_invariants_from_resp(resp)

        # this code is duplicated above, but it's three lines or so
        if key:
            return self.session_state[key]
        return self.session_state

    # ==================== UTILITY ====================
    def get_views(self, collectionId=''):
        ''' Flags are not checked for validity. They're simply
        appended to the end of the url string.'''
        if not collectionId:
            url = "/Users/{}/Views".format(self.session_invariants('UserId'))
        else:
            url = "/Users/{}/Items?parentId={}".format(
                self.session_invariants('UserId'),
                collectionId)
            
        resp = self.get(url, auth=True)
        return resp_to_content_dict(resp)

    def get_live_channels(self):
        # we aren't interested in record count.
        top_level_views = self.get_views()['Items']
        # get the first livetv collection (there is only one)
        livetv_id = self._get_first_colltype(top_level_views, 'livetv')['Id']

        # man this is a verbose API
        livetv_coll = self.get_views(livetv_id)['Items']
        livetv_channels_id = self._get_first_colltype(
            livetv_coll, 'LiveTvChannels')['Id']
        return self.get_views(livetv_channels_id)['Items']


    def get_channel_id(self, channel_name):
        pass


    # ==================== GUTS ====================

    def _get_first_colltype(self, coll, colltype):
        return next(x for x in coll if x['CollectionType'] == colltype)
    
    def _auth_headers(self):
        # do we make posts exclusively with json? should that be here?
        return {
            'Content-type': 'application/json',
            'X-MediaBrowser-Token': self.session_invariants(key='AccessToken')
        }

    def _emby_conn_check(self, conn, error_msg):
        if conn.status_code != 200:
            raise ValueError('''
            Err: {} 
            Username: {}
            sha1: {}
            md5: {}
            Headers: {}
            Content: {}'''.format(
                error_msg,
                self.username,
                sha1(self.password).hexdigest(),
                md5(self.password).hexdigest(),
                conn.headers,
                conn.content))



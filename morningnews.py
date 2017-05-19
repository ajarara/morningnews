import json
import requests
from hashlib import md5, sha1

from cachecontrol import CacheControl

EMBY_AUTH = 'MediaBrowser Client="Emby Mobile", Device="Firefox", DeviceId="27d9f5adc15f875265f6aeb29062218d7a58c717", Version="3.2.10.0"'

EMBY_IP = '192.168.5.151:8096'

# please don't judge this code. It judges me enough. I just need a
# working solution by tomorrow morning.
class EmbyController():

    def __init__(self, username, password, auth=EMBY_AUTH, emby_ip=EMBY_IP):
        self.username = username
        self.password = password.encode('utf-8')  # for hashlib
        self.emby_ip = emby_ip
        self.emby_token_url = "http://{}/emby/Users/authenticatebyname".format(emby_ip)
        self._auth_params = json.dumps(
            {
                'Password': sha1(self.password).hexdigest(),
                'PasswordMd5': md5(self.password).hexdigest(),
                'Username': self.username
            }
        )
        self._auth_headers = {
            'Content-type': 'application/json',
            'x-emby-authorization': auth,
            'Content-Length': '{}'.format(len(self._auth_params))
            }
        self.sess = CacheControl(requests.session())
        self.api_key = None
        self.id = None
        
        
    def _get_api(self):
        resp =  self.sess.post(
            self.emby_token_url,
            data = self._auth_params,
            headers = self._auth_headers)
        if resp.status != 200:
            raise ValueError()
        return json.loads(resp.content.decode('utf-8'))

    

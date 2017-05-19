import json
import requests
from hashlib import md5, sha1

# this is more or less arbitrary, but it will effect the way it's represented in the UI
EMBY_AUTH = 'MediaBrowser Client="Emby Mobile", Device="Firefox", DeviceId="27d9f5adc15f875265f6aeb29062218d7a58c717", Version="3.2.10.0"'

EMBY_IP = '192.168.5.151:8096'

PROTO = 'http://'

# please don't judge this code. It judges me enough. I just need a
# working solution by tomorrow morning.
class EmbyController():

    def __init__(self, username, password, emby_ip=EMBY_IP):
        self.username = username
        self.password = password.encode('utf-8')  # for hashlib
        self.emby_ip = emby_ip
        self.emby_url = PROTO + emby_ip

    def _get_api(self, auth=EMBY_AUTH):
        # are api keys persistent as long as the connection persists? This program might run forever.
        # depending on if I get WoL working...
        emby_token_url = "{}/emby/Users/authenticatebyname".format(self.emby_url)
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
        if resp.status_code != 200:
            raise ValueError('''
            Err: Emby no auth. Username: {}
            sha1: {}
            Headers: {}
            Content: {}'''.format(self.username,
                                  sha1(self.password).hexdigest(),
                                  resp.headers,
                                  resp.content))
        return resp
    

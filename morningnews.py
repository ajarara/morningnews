import json
import requests
from hashlib import md5, sha1


EMBY_AUTH = 'MediaBrowser Client="Emby Mobile", Device="Firefox", DeviceId="27d9f5adc15f875265f6aeb29062218d7a58c717", Version="3.2.10.0"'

EMBY_IP = '192.168.5.151:8096'

class EmbyController():

    def __init__(self, username, password, auth=EMBY_AUTH, emby_ip=EMBY_IP):
        self.username = username
        self.password = password.encode('utf-8')  # for hashlib
        self.emby_ip = emby_ip
        self.emby_token_url = "http://{}/emby/Users/authenticatebyname".format(emby_ip)
        self.params = json.dumps(
            {
                'Password': sha1(self.password).hexdigest(),
                'PasswordMd5': md5(self.password).hexdigest(),
                'Username': self.username
            }
        )
        self.headers = {
            'Content-type': 'application/json',
            
'x-emby-authorization': auth,
            'Content-Length': '{}'.format(len(self.params))
            }
        self.resp = None
        self.token = None

    def authenticate(self):
        resp = requests.post(self.emby_token_url,
                             data=self.params,
                             headers = self.headers)
        if resp.status_code != 200:
            print('''
            Err: Emby no auth. Username: {}
            sha1: {}
            Headers: {}
            Content: {}'''.format(self.username,
                                  sha1(self.password).hexdigest(),
                                  resp.headers,
                                  resp.content))
        self.resp = resp
        return resp

    def jsonify_resp(self):
        if not self.resp:
            self.authenticate()
        return json.loads(self.resp.content.decode('utf-8'))

    def get_token(self):
        if not self.token:
            self.token = self.jsonify_resp()['AccessToken']
        return self.token


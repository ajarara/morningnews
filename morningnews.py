import json
import requests
from hashlib import md5, sha1


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
        # this will be mutated once we've authed with the token
        self.auth_headers = None
        # this will be mutated once we've hit Emby's api
        self.resp = None
        # likewise as above
        self.token = None
        # eugh
        self.props = None
        self.library = None
        
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
                                  resp.content),
                  Flush=True)
        self.resp = resp
        return resp

    def jsonify_resp(self):
        if not self.resp:
            self.authenticate()
        if not self.props:
            self.props = json.loads(self.resp.content.decode('utf-8'))
        return self.props

    def get_token(self):
        if not self.token:
            self.token = self.jsonify_resp()['AccessToken']
        self.auth_headers = self.headers.copy().update(
            {'X-MediaBrowser-Token': self.token})
        return self.token

    # this indentation plays mind tricks. Don't trust it.
    def get_library(self):
        if not self.library:
            self.library = requests.get(
                "http://{}{}".format(
                    self.emby_ip,
                    "/Users/{}/Views".format(
                        self.jsonify_resp()['SessionInfo']['UserId'])),
                headers=self.auth_headers)
        return self.library
            

    def get_live_tv(self):
        return requests.get(
            "http://{}{}".format(
                self.emby_ip,
                "/Users/{}/Items?parentId={}".format(
                    self.jsonify_resp()['SessionInfo']['UserId'],
                    self.get_library.content['Items'])),
            headers=self.auth_headers)

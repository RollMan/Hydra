# -*- coding: utf-8 -*-
import string
import random
import time
import urllib.request
import urllib.parse
import hmac
import hashlib
import base64
import json


def random_chr(len):
    return ''.join(random.choice(string.ascii_letters) for x in range(len))

class Twitter:
    oauth_token = {}

    def authorize_twitter(self,apikey, apisec):
        # Authorize
        # access_token = ''
        # access_token_secret = ''
        req_url = 'https://api.twitter.com/oauth/request_token'
        auth_param = {
            'oauth_callback': 'oob',
            'oauth_consumer_key': apikey,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': int(time.time()),
            'oauth_nonce': random_chr(30),
            'oauth_version': '1.0',
        }
        # Creage signature for OAuth
        auth_param_str = '&'.join([
                                   '{}={}'.format(urllib.parse.quote(str(key), ''),
                                                  urllib.parse.quote(str(auth_param[key]), ''))
                                   for key in sorted(auth_param)
                                   ])
        message = '{}&{}&{}'.format(
                                    'POST',
                                    urllib.parse.quote(req_url, ''),
                                    urllib.parse.quote(auth_param_str)
                                   )
        key = '{}&{}'.format(apisec, '')
        signature = hmac.new(
                             key.encode('utf-8'),
                             message.encode('utf-8'),
                             hashlib.sha1
                            )
        digest_base64 = base64.encodestring(signature.digest()).decode('ascii').strip()
        auth_param['oauth_signature'] = digest_base64

        # Send request
        res = urllib.request.urlopen(
                                     req_url,
                                     data=urllib.parse.urlencode(auth_param).encode('ascii')
                                    ).read()

        oauth_token = {
                       key.split('=')[0]: key.split('=')[1] for key in res.decode('ascii').split('&')
                      }
        print("Visit this page and authoricate.\nhttps://api.twitter.com/oauth/authorize?oauth_token={}" .format(oauth_token['oauth_token']))

        oauth_token_url = "https://api.twitter.com/oauth/access_token"
        oauth_verifier = int(input("PIN : "))
        auth_param = {
            'oauth_consumer_key': apikey,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': int(time.time()),
            'oauth_nonce': random_chr(30),
            'oauth_version': '1.0',
            'oauth_token': oauth_token['oauth_token'],
            'oauth_verifier': oauth_verifier
        }
        auth_param_str = '&'.join([
                                   '{}={}'.format(
                                                  urllib.parse.quote(str(key), ''),
                                                  urllib.parse.quote(str(auth_param[key]), '')
                                                 )
                                   for key in sorted(auth_param)
                                 ])
        message = '{}&{}&{}'.format(
                                    'POST',
                                    urllib.parse.quote(req_url, ''),
                                    urllib.parse.quote(auth_param_str)
                                   )
        key = '{}&{}'.format(apisec, '')
        signature = hmac.new(
                             key.encode('utf-8'),
                             message.encode('utf-8'),
                             hashlib.sha1
                            )
        digest_base64 = base64.encodestring(signature.digest()).decode('ascii').strip()
        auth_param['oauth_signature'] = digest_base64
        access_token_req = urllib.request.Request(
                                                  oauth_token_url,
                                                  data=urllib.parse.urlencode(auth_param).encode('utf-8'),
                                                  headers={'Authorization': 'OAuth'}
                                                 )
        res = urllib.request.urlopen(access_token_req).read()
        self.oauth_token = {key.split('=')[0]: key.split( '=')[1] for key in res.decode('ascii').split('&')}

    def request(self, apikey, apisec, url, content, method):
        param = {
            'oauth_consumer_key': apikey,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': int(time.time()),
            'oauth_nonce': random_chr(30),
            'oauth_version': '1.0',
            'oauth_token': self.oauth_token['oauth_token']
        }
        param.update(content)
        # for key, value in param.items():
        #    if isinstance(value, str):
        #        param[key] = value.encode('utf-8')
        param_str = '&'.join(['{}={}'.format(urllib.parse.quote(
            str(key), ''), urllib.parse.quote(str(param[key]), ''))for key in sorted(param)])
        message = '{}&{}&{}'.format(
            method, urllib.parse.quote(url, ''), urllib.parse.quote(param_str, ''))
        key = '{}&{}'.format(apisec, self.oauth_token['oauth_token_secret'])
        signature = hmac.new(
            key.encode('utf-8'), message.encode('utf-8'), hashlib.sha1)
        digest_base64 = base64.encodestring(
            signature.digest()).decode('ascii').strip()
        param['oauth_signature'] = digest_base64
        # for key in content:
        #    del param[key]
        header_params_str = ",".join(['{}={}'.format(urllib.parse.quote(str(key), ''), urllib.parse.quote(str(param[key]), ''))for key in sorted(param)])
        if method is "POST":
            req = urllib.request.Request(url, data=urllib.parse.urlencode(param).encode(
                'utf-8'), headers={'Authorization': 'OAuth {}'.format(header_params_str)})
        else:
            req = urllib.request.Request(url + '?' + urllib.parse.urlencode(
                param), headers={'Authorization': 'OAuth {}'.format(header_params_str)})
        res = urllib.request.urlopen(req)
        return res

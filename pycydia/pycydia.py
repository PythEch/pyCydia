"""
    PyCydia
    by switchpwn

    Copyright (c) 2014 Mustafa Gezen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
from hashlib import sha1
from base64 import b64encode
from time import time
import requests, hmac, cgi

__all__ = ['Cydia']

class Cydia(object):
    __all__ = ['checkCydiaPurchase', 'purchaseCompleted', 'getProvider', 'getStatus']
    
    def __init__(self, udid, package_id, vendor, apikey):
        self.udid = udid
        self.package_id = package_id
        self.vendor = vendor
        self.apikey = apikey

        self.state = self.provider = self.status = self.error = None

    # encoding stuff
    def safe_b64enc(self, s):
        return b64encode(s).replace("=", "").replace("/", "_").replace("+", "-")

    def get_hmac(self, query, key):
        return self.safe_b64enc(hmac.new(key, query, sha1).digest())

    # api stuff
    def apiQuery(self):
        query = "api=store-0.9&device=%s&mode=local&nonce=%d&package=%s&timestamp=%d&vendor=%s" % (self.udid, time() * 1e6, self.package_id, time(), self.vendor)
        return query + "&signature=%s" % self.get_hmac(query, self.apikey)

    def checkCydiaPurchase(self):
        request = requests.get('http://cydia.saurik.com/api/check?%s' % self.apiQuery())

        if not request:
            self.error = "Failed to open request to Cydia"
            return False

        if not request.content:
            self.error = "API request failed"
            return False

        qs = cgi.parse_qs(request.content)

        if not qs:
            self.error = "No request content"
            return False

        self.state = qs.get("state", ["uncompleted"])[0]
        self.provider = qs.get("provider", [None])[0]
        self.status = qs.get("status", [None])[0]
        
        return True

    @property
    def purchaseCompleted(self):
        return self.state == "completed"

    @property
    def getProvider(self):
        return self.provider or False

    @property
    def getStatus(self):
        return self.status or False

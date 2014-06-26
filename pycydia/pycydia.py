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
import time, base64, requests, hmac, cgi

__all__ = ['Cydia']

class Cydia(object):
    def __init__(self, udid, package_id, vendor, apikey):
        self.UDID = udid
        self.PACKAGE_ID = package_id
        self.VENDOR = vendor
        self.APIKEY = apikey

        self.STATE = self.PROVIDER = self.STATUS = self.ERROR = None

    # encoding stuff
    def safe_b64enc(self, b64):
        return b64.replace("=", "").replace("/", "_").replace("+", "-")

    def get_hmac(self, query, key):
        tmphmac = hmac.new(key, query, sha1).digest()
        signature = self.safe_b64enc(base64.b64encode(tmphmac))
        return signature

    # api stuff
    def apiQuery(self, udid, package_id, vendor, apiKey):
        query = "api=store-0.9&device=%s&mode=local&nonce=%d&package=%s&timestamp=%d&vendor=%s" % (udid, time.time() * 1e6, package_id, time.time(), vendor)
        return query + "&signature=%s" % self.get_hmac(query, apiKey)

    def checkCydiaPurchase(self):
        query = self.apiQuery(self.UDID, self.PACKAGE_ID, self.VENDOR, self.APIKEY)

        request = requests.get('http://cydia.saurik.com/api/check?%s' % query)

        if not request:
            self.ERROR = "Failed to open request to Cydia"
            return False

        if not request.content:
            self.ERROR = "API request failed"
            return False

        qs = cgi.parse_qs(request.content)

        if not qs:
            self.ERROR = "No request content"
            return False

        self.STATE = qs.get("state", ["uncompleted"])[0]

        self.PROVIDER = qs.get("provider", [None])[0]

        self.STATUS = qs.get("status", [None])[0]
        
        return True

    @property
    def purchaseCompleted(self):
        return self.STATE == "completed"

    @property
    def getProvider(self):
        return self.PROVIDER or False

    @property
    def getStatus(self):
        return self.STATUS or False

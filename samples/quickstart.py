# Copyright 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

import oa2

# These are our OAuth 2 credentials and configuration.

SCOPE = "https://www.googleapis.com/auth/drive.file"
CLIENT_ID = "106404166122-j5hor4rrgva0db5hthn4s4esib2n90n9.apps.googleusercontent.com"
CLIENT_SECRET = "DjLs44AfnAv_eh5zw49Yq7LN"
REDIRECT_URI = "http://example.com/redirect_uri"

# You need some config first. You can use the API however you like, by calling
# in the required values, or declaratively. You don't need to provide the values
# now, you can provide them later when performing OAuth 2.

config1 = oa2.ClientConfig(SCOPE, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)

class MyConfig(oa2.ClientConfig):
    scope = SCOPE
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    redirect_uri = REDIRECT_URI

config2 = MyConfig()

# config1 and config2 are the same.
#
# There are also some client configs that are prefilled for you.

class MyServerConfig(oa2.WebServerAppConfig):
    scope = SCOPE
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    redirect_uri = REDIRECT_URI

class MyInstalledConfig(oa2.InstalledAppConfig):
    scope = SCOPE
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET
    # See we don't need a redirect URI.

# You don't need to provide the values now, you can provide them later when
# performing OAuth 2.

# Once you have a config you can use it to create an OAuth 2 client and use it.

client = oa2.OAuth2(MyInstalledConfig())

# And use it.

print client.get_auth_uri()

# All the methods take parameters to override your config.

print client.get_auth_uri(scope="https://www.googleapis.com/auth/drive")

# When you have a code, you can exchange it for a token.

code = 'JSNSJSKKSL'

# This will fail because it is a bogus code.
try:
  print client.get_token(code)
except:
  pass

# To spin up a local webserver for wizards, there is a convenience. This will
# now perform OAuth 2.

class MyWizardConfig(oa2.LocalWebServerAppConfig):
    scope = SCOPE
    client_id = CLIENT_ID
    client_secret = CLIENT_SECRET

client = oa2.OAuth2(MyWizardConfig())

print oa2.run_local(client)



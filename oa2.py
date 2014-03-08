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

"""Python OAuth 2.0 library and command line token fetcher.

Usage:

1. As a script.

$ oa2 -s https://www.googleapis.com/auth/drive.file

2. As a library for installed app flow and web server flows.

See samples/
"""

import argparse
import BaseHTTPServer
import json
import sys
import urllib
import urlparse
import uuid
import webbrowser


OA2_VERSION = '0.0'


class IHttpClient(object):
  def post(self, uri, data, **kw):
    raise NotImplementedError


class RequestsHttpClient(IHttpClient):
  """Uses requests."""

  NAME = 'requests'

  def post(self, uri, data, **kw):
    import requests
    resp = requests.post(uri, data, **kw)
    return resp.content


class UrllibHttpClient(IHttpClient):
  """Uses urllib from the Python stdlib."""

  NAME = 'urllib'

  def post(self, uri, data, **kw):
    resp = urllib.urlopen(uri, urllib.urlencode(data))
    return json.load(resp)


class HttpClient(object):

  available_clients = {
      UrllibHttpClient.NAME: UrllibHttpClient,
      RequestsHttpClient.NAME: RequestsHttpClient,
  }

  def set_client_type(self, client_type, **config):
      client_type = self.available_clients[client_type]
      return client_type(**config)

  @classmethod
  def using_urllib(cls):
    self = cls()
    self.set_client_type(UrllibHttpClient.NAME)
    return self

  def post(self, uri, data, **kw):
    return self.client.post(uri, data, **kw)


class Config(object):
  """The configuration for OAuth2.

  Contains a client component and a service component.
  """
  client_config = None # ClientConfig
  service_config = None # ServiceConfig

  def __init__(self, service_config=None, client_config=None):
    self.service_config = service_config or self.service_config
    self.client_config = client_config or self.client_config


class ClientConfig(object):
  """Base OAuth2 client configuration."""

  scope = None
  client_id = None
  client_secret = None
  redirect_uri = None
  access_type = None
  approval_prompt = None
  grant_type = None
  state_factory = None

  def __init__(self, scope=None, client_id=None, client_secret=None,
               redirect_uri=None, access_type=None, approval_prompt=None,
               grant_type=None, state_factory=None):
    self.client_id = client_id or self.client_id
    self.client_secret = client_secret or self.client_secret
    self.redirect_uri = redirect_uri or self.redirect_uri
    self.scope = scope or self.scope
    self.state_factory = state_factory or self.state_factory
    access_type = access_type or self.access_type
    approval_prompt=approval_prompt or self.approval_prompt
    grant_type=grant_type or self.grant_type


class WebServerAppConfig(ClientConfig):
  """OAuth2 client configuration suitable for web servers."""
  approval_prompt = 'auto'
  access_type = 'offline'
  response_type = 'code'
  grant_type = 'authorization_code'


class InstalledAppConfig(WebServerAppConfig):
  """OAuth2 client configuration for installed applications."""
  redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'


class LocalWebServerAppConfig(WebServerAppConfig):
  """OAuth2 client configuration for local apps with a temporary web server."""
  redirect_uri = "http://localhost:9898"


class ServiceConfig(object):
  """Base OAuth2 service configuration."""
  token_uri = None
  auth_uri = None
  revoke_uri = None

  def __init__(self, auth_uri=None, token_uri=None, revoke_uri=None):
    self.auth_uri = auth_uri or self.auth_uri
    self.token_uri = token_uri or self.token_uri
    self.revoke_uri = revoke_uri or self.revoke_uri


class Google(ServiceConfig):
  """Google APIs OAuth 2.0 endpoint."""
  auth_uri = 'https://accounts.google.com/o/oauth2/auth'
  token_uri = 'https://accounts.google.com/o/oauth2/token'
  revoke_uri = 'https://accounts.google.com/o/oauth2/revoke'


class InvalidConfiguration(ValueError):
  """The configuration is invalid."""


VALID_RESPONSE_TYPES = set(['code', 'token'])
VALID_ACCESS_TYPES = set(['online', 'offline'])
VALID_APPROVAL_PROMPTS = set(['force', 'auto'])


def get_token(code, token_service_uri, client_id, client_secret, redirect_uri,
              grant_type, http_client=None):
  """Fetches an OAuth 2 token."""
  data = {
      'code': code,
      'client_id': client_id,
      'client_secret': client_secret,
      'redirect_uri': redirect_uri,
      'grant_type': grant_type,
  }
  # Get the default http client
  if http_client == None:
    http_client = UrllibHttpClient()
  resp = http_client.post(token_service_uri, data, verify=False)
  return resp


def get_auth_uri(auth_service, client_id, scope, redirect_uri, response_type,
                 state, access_type, approval_prompt):
  """Generates an authorization uri."""
  errors = []
  if response_type not in VALID_RESPONSE_TYPES:
    errors.append(
        '{0} is not a valid response_type, must be {1}.'.format(
        response_type, VALID_RESPONSE_TYPES))
  if not client_id:
    errors.append('client_id is missing or empty.')
  if not redirect_uri:
    errors.append('redirect_uri is missing or empty.')
  if not scope:
    errors.append('scope is missing or empty.')
  if access_type not in VALID_ACCESS_TYPES:
    errors.append('access_type is invalid.')
  if approval_prompt not in VALID_APPROVAL_PROMPTS:
    errors.append('approval_prompt is invalid')
  if errors:
    raise ValueError('Invalid parameters: {0}'.format('\n'.join(errors)))
  params = {
      'response_type': response_type,
      'client_id': client_id,
      'redirect_uri': redirect_uri,
      'scope': scope,
      'access_type': access_type,
      'approval_prompt': approval_prompt,
      'state': state,
  }
  return '?'.join([auth_service, urllib.urlencode(params)])


class OAuth2(object):
  """A single unit of OAuth2.

  A dance can be created for a configuration and used once for performing
  authorization. It encapsulates the state parameter of OAuth2, which should be
  verified to ensure safety. To reuse a dance, you must pass a state manually to
  get_auth_uri.
  """
  http_client = None

  def __init__(self, client_config=None, service_config=None):
    self.client_config = client_config
    if service_config is None:
      service_config = Google()
    self.service_config = service_config
    self.state = self.get_state()

  def get_auth_uri(self, auth_service=None, client_id=None, scope=None,
                   redirect_uri=None, response_type=None, state=None,
                   access_type=None, approval_prompt=None):
    return get_auth_uri(
        auth_service or self.service_config.auth_uri,
        client_id or self.client_config.client_id,
        scope or self.client_config.scope,
        redirect_uri or self.client_config.redirect_uri,
        response_type or self.client_config.response_type,
        state or self.state,
        access_type or self.client_config.access_type,
        approval_prompt or self.client_config.approval_prompt
    )

  def get_token(self, code, token_service=None, client_id=None,
                client_secret=None, redirect_uri=None, grant_type=None):
    return get_token(
        code,
        token_service or self.service_config.token_uri,
        client_id or self.client_config.client_id,
        client_secret or self.client_config.client_secret,
        redirect_uri or self.client_config.redirect_uri,
        grant_type or self.client_config.grant_type
    )

  def get_state(self):
    if self.client_config.state_factory:
      return self.client_config.state_factory
    else:
      return self.default_state_factory()

  def default_state_factory(self):
    return str(uuid.uuid4())


class LocalRedirectHandler(BaseHTTPServer.BaseHTTPRequestHandler):

  RESPONSE_TEMPLATE = """
  <html>
    <head>
      <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.3/css/bootstrap.min.css" rel="stylesheet">
      <title>Authorization complete.</title>
    </head>
    <body>
      <div class="container">
      <h1>Authorization complete</h1>
      <p calss="text-center">The fetched code was</p>
      <pre onClick="this.select();">{0}</pre>
      <p>This tab can probably be closed.</p>
      </div>
    </body>
  </html>
  """

  def do_GET(self):
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    query = urlparse.parse_qs(urlparse.urlparse(self.path).query)
    code = (query.get('code') and query.get('code')[0]) or None
    self.wfile.write(self.RESPONSE_TEMPLATE.format(code))
    self.server.authorization_code = code


def wait_for_redirect(port=None, host='0.0.0.0'):
  if not port:
    port = 9898
  httpd = BaseHTTPServer.HTTPServer((host, port), LocalRedirectHandler)
  httpd.handle_request()
  return httpd.authorization_code


def run_local(client):
  """Starts a local web server and wait for a redirect."""
  webbrowser.open(client.get_auth_uri())
  code = wait_for_redirect()
  return client.get_token(code)


class WizardClientConfig(LocalWebServerAppConfig):
  """Credentials for the command line script as an installed app."""
  client_id = '106404166122-j5hor4rrgva0db5hthn4s4esib2n90n9.apps.googleusercontent.com'
  client_secret = 'DjLs44AfnAv_eh5zw49Yq7LN'


def main(argv):
  """Entry point for command line script to perform OAuth 2.0."""
  p = argparse.ArgumentParser()
  p.add_argument('-s', '--scope', nargs='+')
  p.add_argument('-o', '--oauth-service', default='google')
  p.add_argument('-i', '--client-id')
  p.add_argument('-x', '--client-secret')
  p.add_argument('-r', '--redirect-uri')
  p.add_argument('-c', '--http-client', default='requests',
                 choices=HttpClient.available_clients)
  p.add_argument('-f', '--client-secrets')
  args = p.parse_args(argv)
  client_args = (args.client_id, args.client_secret, args.client_id)
  if any(client_args) and not all(client_args):
    print('Must provide none of client-id, client-secret and redirect-uri;'
          ' or all of them.')
    p.print_usage()
    return 1
  print args.scope
  if not args.scope:
    print('Scope must be provided.')
    p.print_usage()
    return 1
  config = WizardClientConfig()
  config.scope = ' '.join(args.scope)
  print(run_local(OAuth2(config))['access_token'])
  return 0


def sys_main():
  """Run main with system arguments."""
  sys.exit(main(sys.argv[1:]))


if __name__ == '__main__':
  sys_main()

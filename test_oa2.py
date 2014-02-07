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

def test_installed_app_config_redirect_uri():
  c = oa2.InstalledAppConfig()
  assert 'urn:ietf:wg:oauth:2.0:oob' == c.redirect_uri

def test_local_webserver_app_config_redirect_uri():
  c = oa2.LocalWebServerAppConfig()
  assert 'http://localhost:9898' == c.redirect_uri

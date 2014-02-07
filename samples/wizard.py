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

"""Show how installed apps should grab a token once and keep it for later."""

import oa2

class WizardConfig(oa2.LocalWebServerAppConfig):
  scope = 'https://docs.google.com/feeds'
  client_id = '106404166122-j5hor4rrgva0db5hthn4s4esib2n90n9.apps.googleusercontent.com'
  client_secret = 'DjLs44AfnAv_eh5zw49Yq7LN'

def main():
  client = oa2.OAuth2(WizardConfig())
  print oa2.run_local(client)

if __name__ == '__main__':
  main()

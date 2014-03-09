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

"""oa2 build script."""

from setuptools import setup

import oa2

setup_params = dict(
  name = 'oa2',
  description = oa2.__doc__.splitlines()[0],
  version = oa2.OA2_VERSION,
  author = 'Ali Afshar',
  author_email = 'afshar@google.com',
  url = 'http://github.com/aliafshar/oa2',
  py_modules = ['oa2'],
  entry_points = {'console_scripts': ['oa2 = oa2:sys_main']},
  use_2to3 = True,
)

setup(**setup_params)

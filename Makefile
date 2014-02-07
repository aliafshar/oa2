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

# Common actions for oa2

VE=env

clean:
	rm -rf ${VE} build dist oa2.egg-info *.pyc __pycache__

install: env
	./${VE}/bin/pip install .

env:
	virtualenv ${VE}
	./${VE}/bin/pip install pytest

helpstrap: env install
	./${VE}/bin/oa2 -h

test: install
	./${VE}/bin/py.test test_oa2.py

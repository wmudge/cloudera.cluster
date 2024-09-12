# Copyright 2024 Cloudera, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest

from pprint import pprint

from ansible_collections.cloudera.cluster.plugins.module_utils import thoughts
from ansible_collections.cloudera.cluster.tests.unit import AnsibleExitJson


def test_missing_required(module_args):
    module_args(dict(
      base="Base",
      mixin_one="Mixin One",
      mixin_two="Mixin Two",
      concrete_one="Concrete One"
    ))

    with pytest.raises(AnsibleExitJson) as e:
        thoughts.main()

    pprint(e.value)
    

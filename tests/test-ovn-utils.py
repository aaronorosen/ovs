# Copyright (c) 2016 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from ovs import ovn_utils


class TestOvnUtils(unittest.TestCase):

    def test_parse_match_fail(self):
        expected = "Syntax error at `a' expecting field name."
        result = ovn_utils.parse_match("a")
        self.assertEqual(result, expected)

    def test_parse_match_success(self):
        result = ovn_utils.parse_match(
            'outport == "25560992-3f36-4a8b-bc19-e3f84188ef33" && ip4 && udp')
        self.assertEqual(result, None)

if __name__ == '__main__':
    unittest.main()

# Copyright 2024 Cloudera, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A common functions for Cloudera Manager role management
"""

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
    _parse_output,
)

from cm_client import (
    ApiRole,
    ApiService,
    ClustersResourceApi,
)
from cm_client.rest import ApiException

ROLE_OUTPUT = [
    "commission_state",
    "config_staleness_status",
    "ha_status",
    "health_checks",
    "health_summary",
    # "host_ref",
    "maintenance_mode",
    "maintenance_owners",
    "name",
    # "role_config_group_ref",
    "role_state",
    # "service_ref",
    "tags",
    "type",
    "zoo_keeper_server_mode",
]


def parse_role_result(role: ApiRole) -> dict:
    # Retrieve only the host_id, role_config_group, and service identifiers
    output = dict(
        host_id=role.host_ref.host_id,
        role_config_group_name=role.role_config_group_ref.role_config_group_name,
        service_name=role.service_ref.service_name,
    )
    output.update(_parse_output(role.to_dict(), ROLE_OUTPUT))
    return output
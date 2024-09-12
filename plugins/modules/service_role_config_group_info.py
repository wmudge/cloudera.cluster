# -*- coding: utf-8 -*-

# Copyright 2024 Cloudera, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    RoleModuleMixin,
    parse_role_config_group_result,
)

from cm_client import RoleConfigGroupsResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
module: service_role_config_group_info
short_description: Retrieve information about a cluster service role config group or groups
description:
  - Gather details about a role config group or groups of a service in a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  role_config_group:
    description:
      - The role config group to examine.
      - If undefined, the module will return all role config groups for the service.
      - If the role config group does not exist, the module will return an empty result.
    type: str
    required: yes
    aliases:
      - role_config_group
      - name
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.cluster
  - cloudera.cluster.service
"""

EXAMPLES = r"""
- name: Gather the configuration details for a cluster service role
  cloudera.cluster.service_role_config_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: knox
    role: GATEWAY

- name: Gather the configuration details in 'full' for a cluster service role
  cloudera.cluster.service_role_config_info:
    host: "example.cloudera.internal"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
    service: ecs
    role: ECS
    view: full
"""

RETURN = r"""
role_config_groups:
  description:
    - List of service role config groups.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The unique name of this role config group.
      type: str
      returned: always
    role_type:
      description:
        - The type of the roles in this group.
      type: str
      returned: always
    base:
      description:
        - Flag indicating whether this is a base group.
      type: bool
      returned: always
    display_name:
      description:
        - A user-friendly name of the role config group, as would have been shown in the web UI.
      type: str
      returned: when supported
    service_name:
      description:
        - The service name associated with this role config group.
      type: str
      returned: always
    role_names:
      description:
        - List of role names associated with this role config group.
      type: list
      elements: str
      returned: when supported
"""


class ClusterServiceRoleConfigGroupInfo(RoleModuleMixin, ClouderaManagerModule):
    def __init__(self):
        argument_spec = dict(
            role_config_group=dict(aliases=["role_config_group", "name"]),
        )

        super().__init__(argument_spec=argument_spec, supports_check_mode=True)

    def prepare(self):
        super().prepare()

        # Set the parameters
        self.role_config_group = self.get_param("role_config_group")

        # Initialize the return values
        self.output["role_config_groups"] = []

    def process(self):
        super().process()

        api = RoleConfigGroupsResourceApi(self.api_client)

        results = []
        if self.role_config_group:
            try:
                results = [
                    api.read_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.role_config_group,
                        service_name=self.service,
                    )
                ]
            except ApiException as e:
                if e.status != 404:
                    raise e
        else:
            results = api.read_role_config_groups(
                cluster_name=self.cluster,
                service_name=self.service,
            ).items

        for r in results:
            # Get role membership
            roles = api.read_roles(
                cluster_name=self.cluster,
                service_name=self.service,
                role_config_group_name=r.name,
            )

            self.output["role_config_groups"].append(
                {
                    **parse_role_config_group_result(r),
                    "role_names": [r.name for r in roles.items],
                }
            )


def main():
    ClusterServiceRoleConfigGroupInfo().execute()


if __name__ == "__main__":
    main()

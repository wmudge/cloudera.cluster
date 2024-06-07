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
)

from cm_client import (
    RolesResourceApi,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
module: service_role_config_info
short_description: Retrieve information about the configuration for a cluster service role
description:
  - Gather configuration information about a service role of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  role:
    description:
      - The role to examine.
      - If the role does not exist, the module will return an empty result.
    type: str
    required: yes
    aliases:
      - role_name
      - name
  view:
    description:
      - The view to materialize.
    type: str
    default: summary
    choices:
        - summary
        - full
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
config:
  description:
    - List of service role configurations.
  type: list
  elements: dict
  returned: always
  contains:
    name:
      description:
        - The canonical name that identifies this configuration parameter.
      type: str
      returned: when supported
    value:
      description:
        - The user-defined value.
        - When absent, the default value (if any) will be used.
        - Can also be absent, when enumerating allowed configs.
      type: str
      returned: when supported
    required:
      description:
        - Whether this configuration is required for the object.
        - If any required configuration is not set, operations on the object may not work.
        - Requires I(full) view.
      type: bool
      returned: when supported
    default:
      description:
        - The default value.
        - Requires I(full) view.
      type: str
      returned: when supported
    display_name:
      description:
        - A user-friendly name of the parameters, as would have been shown in the web UI.
        - Requires I(full) view.
      type: str
      returned: when supported
    description:
      description:
        - A textual description of the parameter.
        - Requires I(full) view.
      type: str
      returned: when supported
    related_name:
      description:
        - If applicable, contains the related configuration variable used by the source project.
        - Requires I(full) view.
      type: str
      returned: when supported
    sensitive:
      description:
        - Whether this configuration is sensitive, i.e. contains information such as passwords, which might affect how the value of this configuration might be shared by the caller.
      type: bool
      returned: when supported
    validate_state:
      description:
        - State of the configuration parameter after validation.
        - Requires I(full) view.
      type: str
      returned: when supported
    validation_message:
      description:
        - A message explaining the parameter's validation state.
        - Requires I(full) view.
      type: str
      returned: when supported
    validation_warnings_suppressed:
      description:
        - Whether validation warnings associated with this parameter are suppressed.
        - In general, suppressed validation warnings are hidden in the Cloudera Manager UI.
        - Configurations that do not produce warnings will not contain this field.
        - Requires I(full) view.
      type: bool
      returned: when supported
"""


class ClusterServiceRoleConfigInfo(RoleModuleMixin, ClouderaManagerModule):
    def __init__(self):
        argument_spec = dict(
            role=dict(required=True, aliases=["role_name", "name"]),
            view=dict(
                default="summary",
                choices=["summary", "full"],
            ),
        )

        super().__init__(argument_spec=argument_spec)

    def prepare(self):
        super().prepare()

        # Set the parameters
        self.role = self.get_param("role")
        self.view = self.get_param("view")

        # Initialize the return values
        self.output["config"] = []

    def process(self):
        super().process()

        try:
            results = RolesResourceApi(self.api_client).read_role_config(
                cluster_name=self.cluster,
                role_name=self.role,
                service_name=self.service,
                view=self.view,
            )

            self.output["config"] = [s.to_dict() for s in results.items]
        except ApiException as e:
            if e.status != 404:
                raise e


def main():
    ClusterServiceRoleConfigInfo().execute()


if __name__ == "__main__":
    main()

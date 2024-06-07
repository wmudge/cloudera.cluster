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
    MutationModuleMixin,
    PurgeModuleMixin,
)
from ansible_collections.cloudera.cluster.plugins.module_utils.role_utils import (
    RoleModuleMixin,
    parse_role_config_group_result,
)

from cm_client import (
    ApiRoleConfigGroup,
    ApiRoleConfigGroupList,
    ApiRoleNameList,
    RoleConfigGroupsResourceApi,
)
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
module: service_role_config_group
short_description: Manage a cluster service role config group.
description:
  - Manage a cluster service role config group.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm-client
options:
  role_config_group:
    description:
      - A role config group to manage.
    type: str
    required: True
    aliases:
      - role_config_group_name
      - name
  role_type:
    description:
      - The role type defining the role config group.
      - I(role_type) is only valid during creation.
      - To change the I(role_type) of an existing role config group, you must explicitly delete and recreate the role config group.
    type: str
    required: False
    aliases:
      - type
  display_name:
    description:
      - The display name for this role config group in the Cloudera Manager UI.
  roles:
    description:
      - A list of roles associated, i.e. using, the role config group.
      - If I(purge=False), any new roles will be moved to use the role config group.
      - If I(purge=True), any roles not specified in the list will be reset to the C(base) role config group for the service.
    type: list
    elements: str
    required: False
    aliases:
      - role_association
      - role_membership
      - membership
  state:
    description:
      - The presence or absence of the role config group.
      - On I(state=absent), any associated role will be moved to the service's default group, i.e. the C(base) role config group.
      - "NOTE: you cannot remove a C(base) role config group."
    type: str
    required: False
    choices:
      - present
      - absent
    default: present
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
  - cloudera.cluster.mutation
  - cloudera.cluster.purge
  - cloudera.cluster.cluster
  - cloudera.cluster.service
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: all
"""

EXAMPLES = r"""
- name: Create a role config group
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: HDFS
    role_config_group: Example-DATANODE
    type: DATANODE

- name: Create or update a role config group with role associations
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: HDFS
    type: DATANODE
    role_config_group: Example-DATANODE
    roles:
      - hdfs-DATANODE-a9a5b7d344404d8a304ff4b3779679a1

- name: Append a role association to a role config group
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    role_config_group: Example-DATANODE
    roles:
      - hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac # Now two roles

- name: Update (purge) role associations to a role config group
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    role_config_group: Example-DATANODE
    roles:
      - hdfs-DATANODE-7f3a9da5805a46e3100bae67424355ac # Now only one role
    purge: yes

- name: Reset all role associations to a role config group
  cloudera.cluster.cluster_service_role_config:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: example-service
    role_config_group: Example-DATANODE
    roles: []
    purge: yes

- name: Remove a role config group
  cloudera.cluster.service_role_config_group:
    host: example.cloudera.com
    username: "jane_smith"
    password: "S&peR4Ec*re"
    cluster: example-cluster
    service: HDFS
    role_config_group: Example-DATANODE
    state: absent
-
"""

RETURN = r"""
role_config_group:
  description:
    - A service role config group.
  type: dict
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


class ClusterServiceRoleConfigGroup(
    RoleModuleMixin, PurgeModuleMixin, MutationModuleMixin, ClouderaManagerModule
):
    def __init__(self):
        argument_spec = dict(
            role_config_group=dict(
                required=True, aliases=["role_config_group_name", "name"]
            ),
            display_name=dict(),
            role_type=dict(aliases=["type"]),
            roles=dict(
                type="list",
                elements="str",
                aliases=["role_association", "role_membership", "membership"],
            ),
            state=dict(choices=["present", "absent"], default="present"),
        )

        super().__init__(argument_spec=argument_spec)

    def prepare(self):
        super().prepare()

        # Set the parameters
        self.role_config_group = self.get_param("role_config_group")
        self.role_type = self.get_param("role_type")
        self.display_name = self.get_param("display_name")
        self.roles = self.get_param("roles")
        self.state = self.get_param("state")

        # Initialize the return value
        self.output["role_config_group"] = {}

    def process(self):
        super().process()

        api = RoleConfigGroupsResourceApi(self.api_client)
        existing = None
        existing_roles = []

        try:
            existing = api.read_role_config_group(
                cluster_name=self.cluster,
                role_config_group_name=self.role_config_group,
                service_name=self.service,
            )
            existing_roles = api.read_roles(
                cluster_name=self.cluster,
                role_config_group_name=self.role_config_group,
                service_name=self.service,
            )
        except ApiException as ex:
            if ex.status != 404:
                raise ex

        if self.state == "absent":
            if existing:
                self.output["changed"] = True

                if self.module._diff:
                    self.diff = dict(
                        before=dict(roles=[r.name for r in existing_roles.items]),
                        after={},
                    )

                if not self.module.check_mode:
                    if existing_roles:
                        api.move_roles_to_base_group(
                            cluster_name=self.cluster,
                            service_name=self.service,
                            body=ApiRoleNameList(
                                [r.name for r in existing_roles.items]
                            ),
                        )

                    api.delete_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.role_config_group,
                        service_name=self.service,
                    )

        elif self.state == "present":
            if existing:
                if self.role_type and self.role_type != existing.role_type:
                    self.module.fail_json(
                        msg="Invalid role type. To change the role type of an existing role config group, please destroy and recreate the role config group with the designated role type."
                    )

                if self.display_name and self.display_name != existing.display_name:
                    self.output["changed"] = True

                    if self.module._diff:
                        self.diff["before"].update(display_name=existing.display_name)
                        self.diff["after"].update(display_name=self.display_name)

                    if not self.module.check_mode:
                        api.update_role_config_group(
                            cluster_name=self.cluster,
                            role_config_group_name=self.role_config_group,
                            service_name=self.service,
                            message=self.message,
                            body=ApiRoleConfigGroup(display_name=self.display_name),
                        )

                if self.roles is not None:
                    existing_role_names = set([r.name for r in existing_roles.items])
                    roles_add = set(self.roles) - existing_role_names

                    if self.purge:
                        roles_del = existing_role_names - set(self.roles)
                    else:
                        roles_del = []

                    if self.module._diff:
                        self.diff["before"].update(roles=existing_role_names)
                        self.diff["after"].update(roles=roles_add)

                    if roles_add:
                        self.output["changed"] = True
                        if not self.module.check_mode:
                            api.move_roles(
                                cluster_name=self.cluster,
                                role_config_group_name=self.role_config_group,
                                service_name=self.service,
                                body=ApiRoleNameList(list(roles_add)),
                            )

                    if roles_del:
                        self.output["changed"] = True
                        if not self.module.check_mode:
                            api.move_roles_to_base_group(
                                cluster_name=self.cluster,
                                service_name=self.service,
                                body=ApiRoleNameList(list(roles_del)),
                            )

            else:
                self.output["changed"] = True

                if self.role_type is None:
                    self.module.fail_json(msg="missing required arguments: role_type")

                if self.module._diff:
                    self.diff = dict(
                        before={},
                        after=dict(roles=self.roles),
                    )

                if not self.module.check_mode:
                    payload = ApiRoleConfigGroup(
                        name=self.role_config_group,
                        role_type=self.role_type,
                    )

                    if self.display_name:
                        payload.display_name = self.display_name

                    api.create_role_config_groups(
                        cluster_name=self.cluster,
                        service_name=self.service,
                        body=ApiRoleConfigGroupList([payload]),
                    )

                    if self.roles:
                        api.move_roles(
                            cluster_name=self.cluster,
                            role_config_group_name=self.role_config_group,
                            service_name=self.service,
                            body=ApiRoleNameList(self.roles),
                        )

            if self.output["changed"]:
                self.output["role_config_group"] = parse_role_config_group_result(
                    api.read_role_config_group(
                        cluster_name=self.cluster,
                        role_config_group_name=self.role_config_group,
                        service_name=self.service,
                    )
                )

                self.output["role_config_group"].update(
                    role_names=[
                        r.name
                        for r in api.read_roles(
                            cluster_name=self.cluster,
                            role_config_group_name=self.role_config_group,
                            service_name=self.service,
                        ).items
                    ]
                )

            else:
                self.output["role_config_group"] = {
                    **parse_role_config_group_result(existing),
                    "role_names": [r.name for r in existing_roles.items],
                }

        else:
            self.module.fail_json(msg="Invalid state: " + self.state)


def main():
    ClusterServiceRoleConfigGroup().execute()


if __name__ == "__main__":
    main()

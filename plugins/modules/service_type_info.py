# -*- coding: utf-8 -*-

# # Copyright 2024 Cloudera, Inc.
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

from ansible_collections.cloudera.cluster.plugins.module_utils.cm_utils import (
    ClouderaManagerModule,
)

from cm_client import ClustersResourceApi
from cm_client.rest import ApiException

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
module: service_type_info
short_description: Retrieve the service types of a cluster
description:
  - Gather the available service types of a CDP cluster.
author:
  - "Webster Mudge (@wmudge)"
requirements:
  - cm_client
options:
  cluster:
    description:
      - The cluster to examine.
    type: str
    required: yes
    aliases:
      - cluster_name
      - name
extends_documentation_fragment:
  - cloudera.cluster.cm_options
  - cloudera.cluster.cm_endpoint
"""

EXAMPLES = r"""
- name: Gather service type details
  cloudera.cluster.service_type_info:
    host: "example.cloudera.host"
    username: "jane_person"
    password: "S&peR4Ec*re"
    cluster: ExampleCluster
  register: service_types
"""

RETURN = r"""
service_types:
  description: List of the service types available in the cluster.
  type: list
  elements: str
  sample:
    - RANGER
    - OZONE
    - ICEBERG_REPLICATION
"""


class ClusterServiceTypeInfo(ClouderaManagerModule):
    def __init__(self):
        argument_spec = dict(
            cluster=dict(required=True, aliases=["cluster_name"]),
        )

        super().__init__(argument_spec=argument_spec, supports_check_mode=True)

    def prepare(self):
        super().prepare()

        # Set the parameters
        self.cluster = self.get_param("cluster")

        # Initialize the return values
        self.output["service_types"] = []

    def process(self):
        super().process()

        api = ClustersResourceApi(self.api_client)

        try:
            self.output["service_types"] = (
                api.list_service_types(self.cluster).to_dict().get("items", [])
            )
        except ApiException as e:
            if e.status != 404:
                raise e


def main():
    ClusterServiceTypeInfo().execute()


if __name__ == "__main__":
    main()

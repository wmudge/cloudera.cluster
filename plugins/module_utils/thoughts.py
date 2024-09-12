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


from abc import abstractmethod
from ansible.module_utils.basic import AnsibleModule


class Base(object):
    def __init__(self, *args, argument_spec={}, required_one_of={}, **kwargs): # Spell out all of the kwargs
        # Layer in the base arguments
        argument_spec.update(base=dict(required=True))

        # Now set up the module with the collected parameters
        self.module = AnsibleModule(
            argument_spec=argument_spec, required_one_of=required_one_of, **kwargs
        )
        
        # And then execute the chain of prepare() functions
        self.prepare()
        
        # Lastly, execute the chain of process() functions (which should really only be on the Concrete class)
        self.process()

    def prepare(self):
        self.base = self.module.params["base"]

    @abstractmethod
    def process(self):
        pass


class MixinOne(Base):
    def __init__(self, *args, argument_spec={}, **kwargs):
        argument_spec.update(mixin_one=dict(required=True))
        super(MixinOne, self).__init__(*args, argument_spec=argument_spec, **kwargs)

    def prepare(self):
        # Ensure the execution chain continues
        super(MixinOne, self).prepare()
        self.mixin_one = self.module.params["mixin_one"]
        
    def process(self):
        # This will execute via function chaining
        super(MixinOne, self).process()
        pass
        

class MixinTwo(Base):
    def __init__(self, *args, argument_spec={}, **kwargs):
        argument_spec.update(mixin_two=dict(required=True))
        super(MixinTwo, self).__init__(*args, argument_spec=argument_spec, **kwargs)

    def prepare(self):
        # Ensure the execution chain continues
        super(MixinTwo, self).prepare()
        self.mixin_two = self.module.params["mixin_two"]
        
        
class Concrete(MixinOne, MixinTwo, Base):
    def __init__(self, *args, **kwargs):     
        super(Concrete, self).__init__(*args, **kwargs)
      
    def prepare(self):
        # Execute the function chain
        super(Concrete, self).prepare()
        self.concrete_one = self.module.params["concrete_one"]
        self.concrete_two = self.module.params["concrete_two"]

    def process(self):
        super(Concrete, self).process()
        self.output = "Done"

def main():
    concrete = Concrete(argument_spec=dict(
        concrete_one=dict(),
        concrete_two=dict(),
      ),
      required_one_of=[
        ["concrete_one", "concrete_two"]
      ],
    )

    concrete.module.exit_json(msg="Done", output=concrete.output)


if __name__ == "__main__":
    main()

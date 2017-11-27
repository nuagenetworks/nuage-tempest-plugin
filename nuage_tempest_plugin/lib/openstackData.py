from nuage_tempest_plugin.lib.node import Node
from nuage_tempest_plugin.lib.tree import Tree


class openstackData(object):
    def __init__(self):
        self.resources = Tree()
        self.resources.create_node('CMS', 'CMS')

    def insert_resource(self, tag, parent, os_data=None,
                        vsd_data=None, vsc_data=None,
                        vrs_data=None, user_data=None):
        self.resources.create_node(tag, tag, parent=parent,
                                   os_data=os_data, vrs_data=vrs_data,
                                   vsd_data=vsd_data, vsc_data=vsc_data,
                                   user_data=user_data)

    def print_openstackData(self):
        self.resources.show(line_type="ascii-em")

    def delete_resource(self, tag):
        resp = self.resources.remove_node(tag)
        if resp < 1:
            raise Exception("Resource removal failed.")

    def get_resource(self, tag):
        resp = self.resources.get_node(tag)
        if not isinstance(resp, Node):
            raise Exception("Returned node is not of type Node")
        return resp

    def get_children_resources(self, tag):
        resp = self.resources.children(tag)
        if not isinstance(resp, list):
            raise Exception("Did not get a list")
        return resp

    def is_resource_present(self, tag):
        resp = self.resources.contains(tag)
        return resp

    def move_resource(self, tag, new_parent):
        self.resources.move_node(tag, new_parent)

    def update_resource(self, tag, os_data=None,
                        vsd_data=None, vsc_data=None,
                        vrs_data=None, user_data=None):
        self.resources.update_node(tag, os_data=os_data,
                                   vsd_data=vsd_data, vsc_data=vsc_data,
                                   vrs_data=vrs_data, user_data=user_data)

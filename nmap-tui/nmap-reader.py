from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Header, Footer, Tree, Static
import xml.etree.ElementTree as ET
import json


class VimTree(Tree):
    BINDINGS = [
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
        ("h", "cursor_parent", "Back"),
        ("l", "select_cursor", "Select")
    ]

class NmapReader():
    """ Constructor """
    def __init__(self) -> None:
        self.ip_dict = {}
        self.tree = ET.parse('nmap-scans/home-network-standard.xml')
        self.root = self.tree.getroot()

    def not_empty_list(self, some_list: list) -> bool:
        return True if some_list != [] else False

    def not_none_element(self, some_element) -> bool:
        return True if some_element != None else False


    def get_stat(self, stat: str, state: str, ip: str, host) -> None:
        status = host.find(stat)
        if status != None and status.attrib != {}:
            self.ip_dict[ip].update({stat : status.attrib[state]})

    def get_ports(self, curr_ip: str, host) -> None:
        ports_dict = {}
        ports = host.find('ports').findall('port')
        for port in ports:
            pa = port.attrib
            pnbr = int(pa['portid'])
            pprot = pa['protocol']
            port_dict={}
            port_dict[pnbr] = {}
            port_state = port.find('state').attrib
            port_dict[pnbr].update({'state' : port_state['state']})
            port_service = port.find('service').attrib
            port_dict[pnbr].update({'service' : port_service['name']})
            if 'product' in port_service:
                port_dict[pnbr].update({'product' : port_service['product']})
            if 'version' in port_service:
                port_dict[pnbr].update({'version' : port_service['version']})
            if 'devicetype' in port_service:
                port_dict[pnbr].update({'devicetype' : port_service['devicetype']})
            ports_dict.setdefault(pprot, {}).update(port_dict)

        if ports_dict != {}:
            self.ip_dict[curr_ip].update({'ports' : ports_dict})


    def create_ip_dict(self):
        for hosts in self.root.iter('host'):
            curr_ip = ""
            addrs = hosts.findall('address')
            for addr in addrs:
                addrtype = addr.attrib['addrtype']
                if addrtype == 'ipv4':
                    curr_ip = addr.attrib['addr']
                    self.ip_dict[curr_ip] = {}
            for addr in addrs:
                addrtype = addr.attrib['addrtype']
                if addrtype == 'mac':
                    self.ip_dict[curr_ip].update({'mac' : addr.attrib['addr']})
                    if 'vendor' in addr.attrib:
                        self.ip_dict[curr_ip].update({'vendor' : addr.attrib['vendor']})
            self.get_stat('status', 'state', curr_ip, hosts)
            self.get_stat('hostname', 'name', curr_ip, hosts.find('hostnames'))
            self.get_ports(curr_ip, hosts)
        return self.ip_dict


class NmapReaderApp(App):

    CSS = """
    Horizontal {
        height: 1fr;
    }

    VimTree {
        width: 1fr;
        height: 1fr;
        border: round green;
    }

    Static {
        width: 3fr;
        height: 1fr;
        border: round blue;
    }
    """

    ip_dict = {}

    def create_tree(self, ip_list) -> VimTree:
        tree: Tree[str] = VimTree("IPs")
        tree.root.expand()
        ip_list_sort = ip_list.copy()
        ip_list_sort.sort()
        ip_tree = {}
        for l in ip_list_sort:
            ip = ".".join(l.split(".")[:-1]) + ".*"
            ip_tree.setdefault(ip, []).append(l)
        for root_ip in ip_tree:
            if len(ip_tree[root_ip]) == 1:
                tree.root.add_leaf(ip_tree[root_ip][0])
            else:
                temp = tree.root.add(root_ip, expand=False) if len(ip_tree[root_ip]) > 16 else tree.root.add(root_ip, expand=True)
                for ip in ip_tree[root_ip]:
                    temp.add_leaf(ip)
        return tree

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node = event.node
        ip = str(node.label)
        if ip in self.ip_dict:
            self.details.update(json.dumps(self.ip_dict[ip], indent = 3))
        elif ip == "IPs":
            self.details.update(json.dumps(self.ip_dict, indent = 3))

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
        nmap_reader = NmapReader()
        self.ip_dict = nmap_reader.create_ip_dict()
        with Horizontal():
            ip_list = list(self.ip_dict.keys())
            self.ip_tree = self.create_tree(ip_list)
            self.details = Static("Select a host to inspect")
            yield self.ip_tree
            yield self.details


if __name__ == "__main__":
    app = NmapReaderApp()
    app.run()

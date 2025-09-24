from .peer import Peer
from .wgkeys import WireGuardKeyGenerator
import configparser
import os
from flask import current_app

class WGServer:
    def __init__(self, interface: dict = None, peers: list = None):
        self.interface = interface if interface else {}
        self.peers = peers if peers else []

    @classmethod
    def create_server_config(cls, port: int, cidr: str, endpoint: str, uprule: str = '', downrule: str = ''):
        priv_key = WireGuardKeyGenerator.generate_private_key()
        interface = {
            "Address": Peer.process_cidr(cidr, 1),
            "ListenPort": str(port),
            "PrivateKey": priv_key,
            "Endpoint": endpoint,
            "PostUp": uprule or '',
            "PostDown": downrule or ''
        }

        interface = {k: v for k, v in interface.items() if v}
        
        wg_server = cls(interface=interface)
        return wg_server, priv_key

    def load_server_config(self):
        self.interface = {k: v for k, v in self.interface.items() if v}

        server_config = self.config_to_string()
        return server_config
    
    def append_server_config(self, file_path='./configs/admin_server.conf'):
        interface_config = configparser.ConfigParser()
        interface_config.read(file_path)
        prev_peers = int(interface_config["Interface"]["Num_Peers"])
        interface_config["Interface"]["Num_Peers"] = str(prev_peers + len(self.peers))
        with open(file_path, 'w') as configfile:
            interface_config.write(configfile)

        peer_config = configparser.ConfigParser()
        for i, peer in enumerate(self.peers, start=1+prev_peers):
            peer_config[f"Peer{i}"] = peer.to_dict()
        with open(file_path, 'a') as configfile:
            peer_config.write(configfile)

    def load_server_config(self):
        self.interface = {k: v for k, v in self.interface.items() if v}

        server_config = self.config_to_string()
        return server_config

    def add_peers_to_config(self, client_configs_list):
        if "Num_Peers" in self.interface:
            num_peers = int(self.interface["Num_Peers"])
        else:
            num_peers = 0
        for idx, client_config in enumerate(client_configs_list):
            peer = Peer(
                client_no=idx + num_peers,
                port=self.interface['ListenPort'],
                private_key='',
                address=client_config['address'],
                public_key=WireGuardKeyGenerator.generate_public_key(client_config['priv_key']),
                endpoint=client_config['endpoint'],
                allowed_ips=client_config['allowed_ips'],
                dns=client_config['dns'],
                preshared_key=client_config.get('pre_key')
            )
            self.add_peer(peer)
        self.interface["Num_Peers"] = str(len(self.peers) + num_peers)

    def set_interface_info(self, **kwargs):
        for key, value in kwargs.items():
            if value is not None:
                self.interface[key] = value

    def add_peer(self, peer: Peer):
        if isinstance(peer, Peer):
            self.peers.append(peer)

    def remove_peer(self, public_key: str):
        self.peers = [p for p in self.peers if p.public_key != public_key]

    def generate_keys_and_save_to_file(self, file_path: str):
        private_key, public_key = WireGuardKeyGenerator.generate_key_pair()
        if not private_key or not public_key:
            print("Key generation failed.")
            return 
        self.interface['PrivateKey'] = private_key
        self.to_file(file_path)

    def to_file(self, file_path: str):
        config = configparser.ConfigParser()
        config["Interface"] = self.interface
        for i, peer in enumerate(self.peers, start=1):
            config[f"Peer{i}"] = peer.to_dict()
        with open(file_path, 'w') as configfile:
            config.write(configfile)

    @classmethod
    def from_file(cls, file_path: str):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{file_path} does not exist.")
        
        config = configparser.ConfigParser()
        config.read(file_path)

        interface = dict(config["Interface"])
        peers = [Peer.from_dict(dict(config[section])) 
                 for section in config.sections() if section.startswith("Peer")]

        return cls(interface, peers)

    def config_to_string(self):
        config_lines = ["[Interface]"]
        config_lines.extend(f"{key} = {value}" for key, value in self.interface.items())
        
        for peer in self.peers:
            config_lines.append("\n[Peer]")
            config_lines.extend(f"{key} = {value}" for key, value in peer.to_dict().items())

        return "\n".join(config_lines)
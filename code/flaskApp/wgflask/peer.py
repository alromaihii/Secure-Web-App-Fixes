from .wgkeys import WireGuardKeyGenerator
import qrcode
import io
import base64
from flask import current_app

class Peer:
    def __init__(self, client_no: int, port: int, private_key: str, address: str, public_key: str, 
                 endpoint: str, allowed_ips: str, dns: str, preshared_key: str = None):
        self.client_no = client_no
        self.port = port
        self.private_key = private_key
        self.address = address
        self.public_key = public_key
        self.endpoint = endpoint
        self.allowed_ips = allowed_ips
        self.dns = dns
        self.preshared_key = preshared_key

    def to_dict(self):
        _dict = {
            "PublicKey": str(self.public_key),
            "Endpoint": str(self.endpoint),
            "AllowedIPs": str(self.allowed_ips),
            "Address": str(self.address),
            "PrivateKey": str(self.private_key),
            "DNS": str(self.dns),
            "PresharedKey": str(self.preshared_key) if self.preshared_key else ''
        }
        return {k: v for k, v in _dict.items() if ((v != '') and (v is not None) and (v != 'None'))}
        
    @staticmethod
    def generate_key():
        return WireGuardKeyGenerator.generate_private_key()

    @staticmethod
    def generate_preshared_key():
        return WireGuardKeyGenerator.generate_preshared_key()

    @staticmethod
    def process_cidr(cidr, octet, new_mask=None):
        ip_part, mask = cidr.split('/')
        octets = ip_part.split('.')
        octets[-1] = str(octet)
        mask = new_mask if new_mask is not None else mask
        return f"{'.'.join(octets)}/{mask}"

    @classmethod
    def from_config(cls, client_no, port, cidr, allowed_ips, endpoint, dns, preshared, server_pub_key):
        private_key = cls.generate_key()
        address = cls.process_cidr(cidr, client_no, new_mask=32)
        preshared_key = cls.generate_preshared_key() if preshared else None

        config_lines = [
            "[Interface]",
            f"Address = {address}",
            f"ListenPort = {port}",
            f"PrivateKey = {private_key}"
        ]
        if dns != 'None' and dns is not None:
            config_lines.append(f"DNS = {dns}")

        config_lines.append("[Peer]")
        config_lines.append(f"PublicKey = {server_pub_key}")
        if preshared_key:
            config_lines.append(f"PresharedKey = {preshared_key}")
        config_lines.append(f"AllowedIPs = {allowed_ips}")
        if endpoint:
            config_lines.append(f"Endpoint = {endpoint}")
        config = "\n".join(config_lines)

        return cls(client_no, port, private_key, address, server_pub_key, endpoint, allowed_ips, dns, preshared_key), config

    @classmethod
    def load_client_configs(cls, clients, port, cidr, allowed_ips, endpoint, dns, preshared, server_pub_key, num_peers=2):
        client_configs = []
        for i in range(num_peers, clients + num_peers):
            peer, config = cls.from_config(i, port, cidr, allowed_ips, endpoint, dns, preshared, server_pub_key)
            client_dict = {
                "config": config,
                "qr": cls.load_client_qr(config),
                "priv_key": peer.private_key,
                "address": peer.address,
                "allowed_ips": peer.allowed_ips,
                "endpoint": peer.endpoint,
                "dns": peer.dns
            }
            if peer.preshared_key:
                client_dict["pre_key"] = peer.preshared_key
            client_configs.append(client_dict)
        return client_configs

   
    @classmethod 
    def load_client_qr(cls, text):
        qr = qrcode.QRCode()
        qr.add_data(text)
        qr_img = qr.make_image(fill='black', back_color='white')
        img_io = io.BytesIO()
        qr_img.save(img_io, 'PNG')
        img_io.seek(0)
        img_b64 = base64.b64encode(img_io.read()).decode('utf-8')
        return img_b64
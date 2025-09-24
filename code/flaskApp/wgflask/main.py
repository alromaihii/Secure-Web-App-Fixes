import sys
import qrcode
import io
import base64
import os
from flask import Blueprint, render_template, request, send_from_directory, current_app, abort, flash, redirect, url_for, session
from . import db
from flask_login import login_required, current_user
from .forms import AdminWGForm, UserWGForm
from .wgkeys import WireGuardKeyGenerator
from functools import wraps
from .peer import Peer
from .wgconfig import WGServer
import configparser

main = Blueprint('main', __name__)

@main.route('/')
def index():
	return render_template('index.html')

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if (session.get('role') == 'admin'):
        form = AdminWGForm(request.form)
    else:
        form = UserWGForm(request.form)
    server_config = None
    client_configs = [{"config": None, "qr": None}]
    
    if (form.validate_on_submit()) and (session.get('role') == 'admin'):
        port = form.port.data
        clients = form.clients.data
        cidr = form.cidr.data
        allowed_ips = form.allowed_ips.data
        endpoint = form.endpoint.data
        dns = form.dns.data
        uprule = form.uprule.data
        downrule = form.downrule.data
        preshared = form.preshared.data

        # Create server configuration using WGServer
        wg_server, priv_key = WGServer.create_server_config(port, cidr, endpoint, uprule, downrule)
        server_pub_key = WireGuardKeyGenerator.generate_public_key(priv_key)

        # Generate client configurations
        client_configs = Peer.load_client_configs(
            clients=clients,
            port=port,
            cidr=cidr,
            allowed_ips=allowed_ips,
            endpoint=endpoint,
            dns=dns,
            preshared=preshared,
            server_pub_key=server_pub_key
        )

        # Add peers to the server configuration
        wg_server.add_peers_to_config(client_configs)
        server_config = wg_server.load_server_config()

        # Save server and client configurations
        wg_server.to_file(os.path.join(
            current_app.config['CONFIG_DIR'], 
            f"admin_server.conf"
        ))

        save_config_to_file(
            current_app.config['CONFIG_DIR'],
            f"admin_client.conf",
            [config['config'] for config in client_configs]
        )
    elif (form.validate_on_submit()) and (session.get('role') == 'user'):
        clients = form.clients.data
        preshared = form.preshared.data
        allowed_ips = form.allowed_ips.data

        config = configparser.ConfigParser()
        config.read('./configs/admin_server.conf')
        port = config['Interface']['ListenPort']
        cidr = config['Interface']['Address']
        num_peers = int(config['Interface']['Num_Peers'])
        priv_key = config['Interface']['PrivateKey']
        if 'DNS' in config['Interface']:
            dns = config['Interface']['DNS']
        else:
            dns = None
        if 'Endpoint' in config['Interface']:
            endpoint = config['Interface']['Endpoint']
        else:
            endpoint = None
        wg_server = WGServer(interface=config['Interface'])
        server_pub_key = WireGuardKeyGenerator.generate_public_key(priv_key)

        # Generate client configurations
        client_configs = Peer.load_client_configs(
            clients=clients,
            port=port,
            cidr=cidr,
            allowed_ips=allowed_ips,
            endpoint=endpoint,
            dns=dns,
            preshared=preshared,
            server_pub_key=server_pub_key,
            num_peers=num_peers + 2
        )

        # Add peers to the server configuration
        wg_server.add_peers_to_config(client_configs)
        server_config = wg_server.append_server_config()

        save_config_to_file(
            current_app.config['CONFIG_DIR'],
            f"{current_user.name}_client.conf",
            [config['config'] for config in client_configs]
        )

    form_errors = not form.validate_on_submit()
    return render_template(
        'profile.html',
        name=current_user.name,
        form=form,
        server_config=server_config,
        client_configs=client_configs,
        form_errors=form_errors,
        session=session
    )


@main.route('/download', methods=['POST'])
@login_required
def download_file():
    filename = request.form.get('filename')
    if not filename:
        flash('No filename provided.', 'error')
        return redirect('/profile')

    if not os.path.exists(os.path.join(current_app.config['CONFIG_DIR'], filename)):
        flash('File not found.', 'error')
        return redirect('/profile')

    return  send_from_directory(os.path.join("../", current_app.config['CONFIG_DIR']), filename, as_attachment=True)

def save_config_to_file(directory, filename, config):
    filepath = os.path.join(directory, filename)
    with open(filepath, 'w') as f:
        for line in config:
            if "Interface" in line:
                f.write("\n")
            f.write(line)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Access denied.', 'error')
            return redirect(url_for('profile'))
        return f(*args, **kwargs)
    return decorated_function

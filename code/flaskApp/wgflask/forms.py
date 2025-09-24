from tempfile import TemporaryFile
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, BooleanField, ValidationError
from wtforms.validators import DataRequired
import ipaddress

def validate_cidr(form, field):
    """
    Ensure that the CIDR is a valid format
    """
    try:
        ipaddress.ip_network(field.data)
    except ValueError:
        raise ValidationError("Invalid CIDR/Address.")

def validate_ips(form, field):
    """
    Ensure that the allowed IP list contains valid IPs
    """
    ips = field.data.split(",")
    for ip in ips:
        try:
            ipaddress.ip_network(ip)
        except ValueError:
            raise ValidationError("Invalid IP list")

def validate_peers(form, field):
    """
    Allow users to create only a limited number of peers
    """
    if (int(field.data) < 4) and (int(field.data) > 0):
        pass
    else:
        raise ValidationError("Maximum of 3 peers allowed.")

def validate_port(form, field):
    """
    Ensure port number is within valid range
    """
    if (int(field.data) > 0) and (int(field.data) < 65535):
        pass
    else:
        raise ValidationError("Port must be between 0 and 65535")

class AdminWGForm(FlaskForm):
    """
    Form for admin user to define properties of tunnel 
    """
    port        = IntegerField(u"Listen Port", validators=[DataRequired(), validate_port])
    clients     = IntegerField(u"Number of Clients", validators=[DataRequired(), validate_peers])
    cidr        = StringField(u"CIDR", validators=[DataRequired(), validate_cidr])
    allowed_ips = StringField(u"Client Allowed IPs", validators=[DataRequired(), validate_ips])

    endpoint    = StringField(u"Endpoint")
    dns         = StringField(u"DNS", validators=[validate_cidr])
    downrule    = StringField(u"Post-Down Rule")
    uprule      = StringField(u"Post-up Rule")
    preshared   = BooleanField(u"Preshared Keys")

class UserWGForm(FlaskForm):
    """
    User form for connecting to the tunnel
    """
    clients     = IntegerField(u"Number of Clients", validators=[DataRequired(), validate_peers])
    allowed_ips = StringField(u"Client Allowed IPs", validators=[DataRequired(), validate_ips])
    preshared   = BooleanField(u"Preshared Keys")
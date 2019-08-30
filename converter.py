import os
import re
from flask import Flask
from flask import abort
from flask import jsonify
from flask_wtf import FlaskForm
from flask import render_template
from flask import request
from flask_bootstrap import Bootstrap
from wtforms import StringField
from wtforms.validators import InputRequired, MacAddress
import watchtower, logging


class multicastForm(FlaskForm):
   
   mac = StringField('MAC address', validators=[MacAddress()])

def multicast_mac_to_ip(mac_address):
    logger = logging.getLogger(__name__)
    logger.info("Executing function multicast_mac_to_ip")
    mac_bytes = mac_address.split(":")
    ip_mask = 0xe0000000
    ip_mask |= int(mac_bytes[3], 16) << 16
    ip_mask |= int(mac_bytes[4], 16) << 8
    ip_mask |= int(mac_bytes[5], 16)
    result = list()

    for i in range(0,31):
        temp_ip = ip_mask
        temp_ip |= i << 23
        o4 = (temp_ip & 0xff000000) >> 24
        o3 = (temp_ip & 0x00ff0000) >> 16
        o2 = (temp_ip & 0x0000ff00) >> 8
        o1 = (temp_ip & 0x000000ff)
        result.append(str(o4) + "." + str(o3) + "." + str(o2) + "." + str(o1))
    return result


logging.basicConfig(level=logging.INFO)
application = Flask(__name__)
handler = watchtower.CloudWatchLogHandler()
application.logger.addHandler(handler)
logging.getLogger("werkzeug").addHandler(handler)
application.config['SECRET_KEY'] = '443436456542'
Bootstrap(application)


@application.route("/", methods=["GET", "POST"])
def index():

   form = multicastForm()
   if form.validate_on_submit():
      ips = multicast_mac_to_ip(request.form.get("mac"))
      return render_template("home.html", form=form, ips=ips)
   else:
      return render_template("home.html", form=form)


@application.route('/api/v0.1/mac-to-ip', methods=['POST'])
def convert():
    if not request.json or not 'mac' in request.json:
        abort(400)
    mac = request.json['mac']
    r = multicast_mac_to_ip(mac)
    return jsonify(r)


  
if __name__ == "__main__":
    application.run(host="0.0.0.0", debug=True)



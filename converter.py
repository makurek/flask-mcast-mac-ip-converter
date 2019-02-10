import os
from flask import Flask
from flask import render_template
from flask import request
from flask_bootstrap import Bootstrap
from wtforms import StringField
from wtforms.validators import InputRequired, Length, AnyOf

class multicastForm(Form):
   mac = StringField('mac', validators=[InputRequired()])

def multicast_mac_to_ip(mac_address):

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

app = Flask(__name__)
Bootstrap(app)


@app.route("/", methods=["GET", "POST"])
def home():
   form = multicastForm()
   if form.validate_on_submit():
      ips = multicast_mac_to_ip(request.form.get("mac"))
      return render_template("home.html", ips=ips)
   else:
      return render_template("home.html")

  
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)



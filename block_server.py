from pox.core import core
from pox.lib.addresses import IPAddr
from pox.openflow import libopenflow_01 as of
from flask import Flask, request
from threading import Thread

app = Flask(__name__)
connection = None

@app.route('/block', methods=['POST'])
def block_host():
    global connection
    data = request.json
    attacker_ip = data.get("attacker_ip")
    if connection and attacker_ip:
        msg = of.ofp_flow_mod()
        msg.match.nw_src = IPAddr(attacker_ip)
        msg.match.dl_type = 0x0800
        msg.priority = 10000
        msg.actions = []
        connection.send(msg)
        print(f"[!] {attacker_ip} için DROP flow eklendi!")
    return "Block Request Received", 200

def _handle_ConnectionUp(event):
    global connection
    connection = event.connection
    print("[*] Switch ile bağlantı kuruldu, bağlantı kaydedildi.")

def start_server():
    app.run(host='0.0.0.0', port=5001)

def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    server_thread = Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()
    print("[*] POX HTTP Block Server Started on port 5001")


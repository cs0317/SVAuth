#!/usr/bin/env python
"""
SVAuth Python Platform
Time-stamp: <2017-04-28 00:10:33 phuong>
"""

import os
import flask
from flask import Flask, request, session, redirect, render_template, flash, abort, make_response, session

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

max_conckey = 38
IDP = "Facebook"
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    """
    Show an index page with social login buttons
    """
    # if request.remote_addr != "127.0.0.1":
    #     abort(403)
    if "UserID" in request.form and len(request.form["UserID"]) == 0:
        session.clear()
    resp = make_response(render_template("index.html"))
    resp.set_cookie('LandingUrl',
                    '{}://{}'.format(config['WebAppSettings']['scheme'],
                                        config['WebAppSettings']['hostname']
                                        ))
    if "UserID" not in session:
        session["UserID"] = ""
    return resp


# from stackoverflow
def decrypt(key, iv, ciphertext):
    """
    Decrypt a cipher text using AES-256-CBC
    """
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv),
        backend=default_backend()).decryptor()

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


@app.route('/SVAuth/adapters/py/RemoteCreateNewSession.py', methods=['GET'])
def remote_create_new_session():
    """
    Receive encrypted user profile from svauth remote agent
    Decode the encrypted user profile
    Set user profile to current session
    """
    encryptedUserProfile = request.args.get("encryptedUserProfile")
    key = session["key"]
    key = bytes(key, 'utf-8')
    key = key[:32]
    iv = key[:16]
    encryptedUserProfile = bytes(bytearray.fromhex(encryptedUserProfile))
    res = decrypt(key, iv, encryptedUserProfile)
    try:
        res = json.loads(res)
    except:
        res = res[:-2]
        res = json.loads(res)
    fields = ["UserID", "FullName", "Email", "Authority"]
    for field in fields:
        session[field] = res[field]
    return redirect("/")


@app.route('/start', methods=['GET'])
def start():
    """
    Start the login flow by contacting the remote svauth agent
    """
    import hashlib
    max_conckey = 38
    sid_sha256 = hashlib.sha256(
        request.cookies.get('session').encode('utf-8')).hexdigest()
    conckey = sid_sha256[:max_conckey]
    url = '{}://{}:{}/login/{}?conckey={}&concdst={}://{}?{}'.format(
        config['AgentSettings']['scheme'],
        config['AgentSettings']['agentHostname'],
        config['AgentSettings']['port'], IDP, conckey,
        config['WebAppSettings']['scheme'],
        config['WebAppSettings']['hostname'], 
        config['WebAppSettings']['platform']['name'])
    session["key"] = sid_sha256[:max_conckey]
    return redirect(url)


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect("/")


if __name__ == '__main__':
    import json
    global config
    app.debug = True
    app.secret_key = os.urandom(24)
    config_file = "adapter_config.json"
    config_file = "../adapter_config/" + config_file
    # read adapter config
    with open(
            config_file,
            encoding='utf-8') as data_file:
        config = json.loads(data_file.read())
    port = int(os.environ.get('PORT', 80))
    app.run(host='0.0.0.0', port=port)

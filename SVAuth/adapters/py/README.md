# Python adapter for SVAuth

[Live demo on Heroku](https://svauth-python-adapter.herokuapp.com/) 

![Python adapter for SVAuth](https://media.giphy.com/media/xUPGcHE7FCbpkFqV8I/giphy.gif "Demo")

[![Deploy](https://www.herokucdn.com/deploy/button.png)](https://github.com/pmcao/svauth-python-adapter-example)

# Prerequisites
On any machine with Python 3, install requirements:

    pip3 install -r requirements.txt

# Installation

## Run the Python adapter for SVAuth on port 80

    sudo python3 index.py

    Running on http://0.0.0.0:80/
    
Note: you might need `root` permission to run the python webserver on port 80


## Visit localhost page

    http://localhost

## Login with SVAuth

1. Click on the `login` button
2. Authorize `SVAuth` to access your Identity Provider profile
3. Finish! You should see your profile information shown on the web page.

An important thing to note: your login has been verified by `SVAuth`


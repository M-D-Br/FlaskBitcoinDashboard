# FlaskBitcoinDashboard
Python Flask Dashboard made with Bootstrap for watching a Bitcoin node (tried it on Ubuntu, should work on OSX, too). Can be accessed by anyone on the local network, works on both desktop and mobile.

Works with bitcoind/lnd. I may work on a c-lightning version if there's any interest.

Thanks to <a href="https://github.com/wintercooled">@wintercooled</a> for the inspiration.

First up, we'll install virtualenv.

`sudo apt install virtualenv`

Create a directory.

`mkdir dash && cd dash`

Activate the virtual environment.

`source venv/bin/activate`

Download Flask and the Bitcoin RPC tools.

`pip install flask`
`pip install python-bitcoinrpc`

Now for the Lightning part (based off <a href="https://dev.lightning.community/guides/python-grpc/">this guide</a>.

`pip install grpcio grpcio-tools googleapis-common-protos`
`git clone https://github.com/googleapis/googleapis.git`
`curl -o rpc.proto -s https://raw.githubusercontent.com/lightningnetwork/lnd/master/lnrpc/rpc.proto`
`python -m grpc_tools.protoc --proto_path=googleapis:. --python_out=. --grpc_python_out=. rpc.proto`

Almost there. You need to input your own RPC credentials.

`sudo nano app/backend.py`

Edit the variables <i>rpc_user</i>, <i>rpc_password</i>, <i>rpc_port</i> and <i>allowed_ip</i>.

exit that (CTRL+X, y to save the changes) and export the Flask app.

`export FLASK_APP=dashboard.py`

Voila! To run the server:

`flask run --host=0.0.0.0`

Go to any web browser on your network and enter the IP of the node + port 5000, i.e. `192.168.1.1:5000`

CTRL + C to close the server.

Let me know if you have any issues or suggestions.




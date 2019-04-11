
# -*- coding: utf-8 -*- 

from flask import render_template, request
from app import app
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc, os, codecs

#RPC Credentials
rpc_user = "[RPC USER]"
rpc_password = "[RPC PASS]"
rpc_port = [RPC PORT]
allowed_ip = "[MACHINE IP]"
#Your Lightning Directory - Don't forget to add a forward slash at the end.
lnd_dir_location = '[DIRECTORY]'

@app.route('/')
@app.route('/index')
def index():

    try:
        rpc_connect = AuthServiceProxy("http://{}:{}@{}:{}".format(rpc_user,rpc_password,allowed_ip,rpc_port))
        current_block_height = rpc_connect.getblockcount()
        onchain_peers = rpc_connect.getconnectioncount()
        onchain_balance = rpc_connect.getbalance()
        if onchain_balance > 0:
            onchain_balance = u"₿ " + str(onchain_balance)
        else:
            onchain_balance = u"₿ " + str(0)
        bitcoin_version = (rpc_connect.getnetworkinfo()['subversion'])[1:-1].replace("Satoshi:","")
        sync_prog = str(round(rpc_connect.getblockchaininfo()['verificationprogress']*100, 2)) + "%"
        chain_type = rpc_connect.getblockchaininfo()['chain']
        if chain_type == "test":
            chaintype_ln = "testnet"
        else:
            chaintype_ln = "mainnet"
    except:
        current_block_height = onchain_peers = onchain_balance = bitcoin_version = sync_prog = chain_type = "Offline!"

    try: 
        os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
        with open(os.path.expanduser(lnd_dir_location + 'data/chain/bitcoin/{}/admin.macaroon'.format(chaintype_ln)), 'rb') as f:
            macaroon_bytes = f.read()
            macaroon = codecs.encode(macaroon_bytes, 'hex')


        cert = open(os.path.expanduser(lnd_dir_location + '/tls.cert'), 'rb').read()
        creds = grpc.ssl_channel_credentials(cert)
        channel = grpc.secure_channel('localhost:10009', creds)
        stub = lnrpc.LightningStub(channel)

        response = stub.GetInfo(ln.GetInfoRequest(), metadata=[('macaroon', macaroon)])
        balance = stub.WalletBalance(ln.WalletBalanceRequest(), metadata=[('macaroon', macaroon)])
        lightning_channels_act = response.num_active_channels
        lightning_peers = response.num_peers
        offchain_balance = u"ş " + str(balance.total_balance)
        lightning_version = response.version[:5]
        alias = response.alias
    except:

        lightning_channels_act = lightning_peers = offchain_balance = lightning_version = alias = "Offline!"


    return render_template('index.html', current_block_height=current_block_height,
         onchain_peers=onchain_peers, onchain_balance=onchain_balance, 
         bitcoin_version=bitcoin_version, sync_prog=sync_prog, chain_type=chain_type, lightning_channels_act=lightning_channels_act,
         lightning_peers=lightning_peers, offchain_balance=offchain_balance,
         lightning_version=lightning_version, alias=alias)

@app.route('/peerpage', methods=['GET', 'POST'])
def peerpage():
    try:
        rpc_connect = AuthServiceProxy("http://{}:{}@{}:{}".format(rpc_user,rpc_password,allowed_ip,rpc_port))
        chain_type = rpc_connect.getblockchaininfo()['chain']
        if chain_type == "test":
            chaintype_ln = "testnet"
        else:
            chaintype_ln = "mainnet"
        os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
        with open(os.path.expanduser(lnd_dir_location + 'data/chain/bitcoin/{}/admin.macaroon'.format(chaintype_ln)), 'rb') as f:
            macaroon_bytes = f.read()
            macaroon = codecs.encode(macaroon_bytes, 'hex')


        cert = open(os.path.expanduser(lnd_dir_location + 'tls.cert'), 'rb').read()
        creds = grpc.ssl_channel_credentials(cert)
        channel = grpc.secure_channel('localhost:10009', creds)
        stub = lnrpc.LightningStub(channel)

        response = stub.ListPeers(ln.ListPeersRequest(), metadata=[('macaroon', macaroon)])
        show_current_peers = response.peers
        show_current_peers_list = []
        for peer in show_current_peers:
            show_current_peers_list.append(str(peer.pub_key) + "@" + str(peer.address))
        conn = True
        length_of = len(show_current_peers_list)

    except:
        show_current_peers_list = ["Offline!"]
        length_of = 0
        conn = False

    if conn == True:
      if request.method == 'POST':
        response_uri = request.get_data()
        result = response_uri[3:-4].strip()
        for r in (("%40", "@"), ("%3A", ":")):
           result = result.replace(*r)
        def connect(host, port, node_id):
           addr = ln.LightningAddress(pubkey=node_id, host="{}:{}".format(host, port))
           req = ln.ConnectPeerRequest(addr=addr, perm=True)
           stub.ConnectPeer(ln.ConnectPeerRequest(addr=addr,perm=False), metadata=[('macaroon',macaroon)])

        try:
           nodeid, lnhost, lnport = result[:66], result[67:-5], result[-4:]
           result = nodeid + ' ' + lnhost + ' ' + lnport
           connect(lnhost,lnport,nodeid)
           show_current_peers_list.append(" ")
           length_of = len(show_current_peers_list)
           result = "Successfully connected!"
           return render_template('peerpage_.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result=result)

        except:
           pass

    return render_template('peerpage_.html', len=len(show_current_peers_list), length_of=length_of, show_current_peers=show_current_peers_list)                 

@app.route('/peerpage_', methods=['POST', 'GET'])
def peerpage2():
    try:
        rpc_connect = AuthServiceProxy("http://{}:{}@{}:{}".format(rpc_user,rpc_password,allowed_ip,rpc_port))
        chain_type = rpc_connect.getblockchaininfo()['chain']
        if chain_type == "test":
            chaintype_ln = "testnet"
        else:
            chaintype_ln = "mainnet"
        os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
        with open(os.path.expanduser(lnd_dir_location + 'data/chain/bitcoin/{}/admin.macaroon'.format(chaintype_ln)), 'rb') as f:
            macaroon_bytes = f.read()
            macaroon = codecs.encode(macaroon_bytes, 'hex')


        cert = open(os.path.expanduser(lnd_dir_location + 'tls.cert'), 'rb').read()
        creds = grpc.ssl_channel_credentials(cert)
        channel = grpc.secure_channel('localhost:10009', creds)
        stub = lnrpc.LightningStub(channel)

        response = stub.ListPeers(ln.ListPeersRequest(), metadata=[('macaroon', macaroon)])
        show_current_peers = response.peers
        show_current_peers_list = []
        for peer in show_current_peers:
            show_current_peers_list.append(str(peer.pub_key) + "@" + str(peer.address))
        conn = True
        length_of = len(show_current_peers_list)

    except:
        show_current_peers_list = ["Offline!"]
        length_of = 0
        conn = False

    if conn == True:
      if request.method == 'POST':
        response_uri = request.get_data()
        result = response_uri[3:-4].strip()
        for r in (("%40", "@"), ("%3A", ":")):
           result = result.replace(*r)
        def connect(host, port, node_id):
           addr = ln.LightningAddress(pubkey=node_id, host="{}:{}".format(host, port))
           req = ln.ConnectPeerRequest(addr=addr, perm=True)
           stub.ConnectPeer(ln.ConnectPeerRequest(addr=addr,perm=False), metadata=[('macaroon',macaroon)])

        try:
           nodeid, lnhost, lnport = result[:66], result[67:-5], result[-4:]
           result = nodeid + ' ' + lnhost + ' ' + lnport
           connect(lnhost,lnport,nodeid)
           show_current_peers_list.append(" ")
           length_of = len(show_current_peers_list)
           result = "Successfully connected!"
           return render_template('peerpage_.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result=result)

        except:
           pass

    return render_template('peerpage_.html', len=len(show_current_peers_list), length_of=length_of, show_current_peers=show_current_peers_list)     


# -*- coding: utf-8 -*- 

from flask import render_template
from app import app
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc, os, codecs


@app.route('/')
@app.route('/index')
def index():

    #RPC Credentials
    rpc_user = ['your bitcoin rpc username']
    rpc_password = ['your bitcoin rpc password']
    rpc_port = ['RPC port']
    allowed_ip = ['IP of the device']
    #Your Lightning Directory – don't forget the forward slash at the end
    lnd_dir_location = '[lnd directory location]'

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



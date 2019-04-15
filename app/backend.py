
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
        bitcoin_version = (rpc_connect.getnetworkinfo()['subversion'])[1:-1].replace("Satoshi:","")
        sync_prog = str(round(rpc_connect.getblockchaininfo()['verificationprogress']*100, 2)) + "%"
        chain_type = rpc_connect.getblockchaininfo()['chain']
        if onchain_balance > 0 and chain_type == "main":
            onchain_balance = u"₿ " + str(onchain_balance)
        elif onchain_balance == 0:
            onchain_balance = u"₿ " + str(0)
        elif onchain_balance > 0 and chain_type == "test":
            onchain_balance = u"t₿ " + str(onchain_balance)          
        else:
            onchain_balance = u"t₿ " + str(0)

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

        cert = open(os.path.expanduser(lnd_dir_location + 'tls.cert'), 'rb').read()
        creds = grpc.ssl_channel_credentials(cert)
        channel = grpc.secure_channel('localhost:10009', creds)
        stub = lnrpc.LightningStub(channel)

        response = stub.GetInfo(ln.GetInfoRequest(), metadata=[('macaroon', macaroon)])
        satbalance = stub.ChannelBalance(ln.ChannelBalanceRequest(), metadata=[('macaroon', macaroon)])
        lightning_channels_act = response.num_active_channels
        lightning_peers = response.num_peers
        offchain_balance = u"ş " + str(format(satbalance.balance,','))
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
        if request.form['action'] == "connectbutton":
          if len(request.form['text']) > 10:
            response_uri = str(request.form['text'])
            result = response_uri.strip()

            def connect(host, port, node_id):
               addr = ln.LightningAddress(pubkey=node_id, host="{}:{}".format(host, port))
               req = ln.ConnectPeerRequest(addr=addr, perm=True)
               stub.ConnectPeer(ln.ConnectPeerRequest(addr=addr,perm=False), metadata=[('macaroon',macaroon)])
            try:
               nodeid, lnhost, lnport = result[:66], result[67:-5], result[-4:]
               connect(lnhost,lnport,nodeid)
               show_current_peers_list.append(result)
               length_of = len(show_current_peers_list)
               result = "Successfully connected!"
               return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="SuccessCon")
            except:
               return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseCon")
          else:
            return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseCon")
        else:
          if len(request.form['text']) > 10:
            response_uri = str(request.form['text'])
            result = response_uri.strip()
            def disconnect(pubkey):
                req = ln.DisconnectPeerRequest(pub_key=pubkey)
                stub.DisconnectPeer(ln.DisconnectPeerRequest(pub_key=pubkey), metadata=[('macaroon',macaroon)])
            try:
                disconnect(result)
                del show_current_peers_list[-1]
                length_of = len(show_current_peers_list)
                return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="SuccessDis")
            except:
                return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseDis")
          else:
            return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseDis")
    return render_template('peerpage.html', len=len(show_current_peers_list), length_of=length_of, show_current_peers=show_current_peers_list)               


@app.route('/makepayment', methods=['POST', 'GET'])
def makepayment():
     try:
        rpc_connect = AuthServiceProxy("http://{}:{}@{}:{}".format(rpc_user,rpc_password,allowed_ip,rpc_port))
        current_block_height = rpc_connect.getblockcount()
        onchain_peers = rpc_connect.getconnectioncount()
        chain_type = rpc_connect.getblockchaininfo()['chain']
        onchain_balance = rpc_connect.getbalance()
        fasttx = rpc_connect.estimatesmartfee(2)
        medtx = rpc_connect.estimatesmartfee(6)
        slowtx = rpc_connect.estimatesmartfee(12)

        if chain_type == "main":
            fasttxrate = u"~₿ " + str(fasttx['feerate'])
            medtxrate = u"~₿ " + str(medtx['feerate'])
            slowtxrate = u"~₿ " + str(slowtx['feerate'])
        else:
            fasttxrate = u"~t₿ " + str(fasttx['feerate'])
            medtxrate = u"~t₿ " + str(medtx['feerate'])
            slowtxrate = u"~t₿ " + str(slowtx['feerate'])

        if onchain_balance > 0 and chain_type == "main":
            onchain_balance = u"₿ " + str(onchain_balance)
        elif onchain_balance == 0:
            onchain_balance = u"₿ " + str(0)
        elif onchain_balance > 0 and chain_type == "test":
            onchain_balance = u"t₿ " + str(onchain_balance)        
        else:
            onchain_balance = u"t₿ " + str(0)
        if chain_type == "test":
            chaintype_ln = "testnet"
        else:
            chaintype_ln = "mainnet"

        conn = True
     except:
        onchain_balance = "Offline!"
        fasttxrate, medtxrate, slowtxrate = "", "", ""
        conn = False

     try:
      os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
      with open(os.path.expanduser(lnd_dir_location + 'data/chain/bitcoin/{}/admin.macaroon'.format(chaintype_ln)), 'rb') as f:
        macaroon_bytes = f.read()
        macaroon = codecs.encode(macaroon_bytes, 'hex')
      cert = open(os.path.expanduser(lnd_dir_location + 'tls.cert'), 'rb').read()
      creds = grpc.ssl_channel_credentials(cert)
      channel = grpc.secure_channel('localhost:10009', creds)
      stub = lnrpc.LightningStub(channel)

      satbalance = stub.ChannelBalance(ln.ChannelBalanceRequest(), metadata=[('macaroon', macaroon)])
      offchain_balance = u"ş " + str(format(satbalance.balance,','))
     except:
      offchain_balance = "Offline!"

     if conn == True:
      if request.method == 'POST':
        if request.form['action'] == "sendbutton":
          if request.form['fee'] == "medfee":
            try:
              txid = rpc_connect.sendtoaddress(request.form['address'], request.form['amt'], "", "", False, True, medtx['blocks'])

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=True, txid=txid, offchain_balance=offchain_balance)
            except:

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance)

          elif request.form['fee'] == "highfee":
            try:
              txid = rpc_connect.sendtoaddress(request.form['address'], request.form['amt'], "", "", False, True, fasttx['blocks'])

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=True, txid=txid, offchain_balance=offchain_balance)
            except:

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance) 
          elif request.form['fee'] == "lowfee":
            try:
              txid = rpc_connect.sendtoaddress(request.form['address'], request.form['amt'], "", "", False, True, slowtx['blocks'])

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=True, txid=txid, offchain_balance=offchain_balance)
            except:
              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance)

        if request.form['action'] == "decodereq":
            try:
              os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
              with open(os.path.expanduser(lnd_dir_location + 'data/chain/bitcoin/{}/admin.macaroon'.format(chaintype_ln)), 'rb') as f:
                macaroon_bytes = f.read()
                macaroon = codecs.encode(macaroon_bytes, 'hex')
              cert = open(os.path.expanduser(lnd_dir_location + 'tls.cert'), 'rb').read()
              creds = grpc.ssl_channel_credentials(cert)
              channel = grpc.secure_channel('localhost:10009', creds)
              stub = lnrpc.LightningStub(channel)
              if len(request.form['reqtext']) > 20:
                req_whole = request.form['reqtext']
                decoded_req = stub.DecodePayReq(ln.PayReqString(pay_req=req_whole), metadata=[('macaroon', macaroon)])
                req_desc = decoded_req.description
                req_amt = u"ş " + str(format(decoded_req.num_satoshis,','))
                req_to = decoded_req.destination
                with open("invoice.txt",'wb') as invoicefile:
                 invoicefile.write(req_whole)
                 invoicefile.close()
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", req_desc=req_desc, req_amt=req_amt, req_to=req_to, switch=True, offchain_balance=offchain_balance, req_whole=req_whole)
              else:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", switch=False, offchain_balance=offchain_balance)
            except:
              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", switch=False, offchain_balance=offchain_balance)
        if request.form['action'] == "confirmbutton":
            try:
              os.environ["GRPC_SSL_CIPHER_SUITES"] = 'HIGH+ECDSA'
              with open(os.path.expanduser(lnd_dir_location + 'data/chain/bitcoin/{}/admin.macaroon'.format(chaintype_ln)), 'rb') as f:
                macaroon_bytes = f.read()
                macaroon = codecs.encode(macaroon_bytes, 'hex')
              cert = open(os.path.expanduser(lnd_dir_location + 'tls.cert'), 'rb').read()
              creds = grpc.ssl_channel_credentials(cert)
              channel = grpc.secure_channel('localhost:10009', creds)
              stub = lnrpc.LightningStub(channel)
              with open("invoice.txt",'r') as invoicefile:
                invoice_confirmed = invoicefile.read()    

              try:
               result = stub.SendPaymentSync(ln.SendRequest(payment_request=str(invoice_confirmed)), metadata=[('macaroon', macaroon)])
               if result.payment_error:
                 return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance, successln=False, error=result.payment_error)
               else:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance, successln=True, preimage=hexlify(result.payment_preimage))
              except:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance)
            except:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance)

     return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance)      

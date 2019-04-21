
# -*- coding: utf-8 -*- 

from flask import render_template, request
from app import app
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import rpc_pb2 as ln
import rpc_pb2_grpc as lnrpc
import grpc, os, codecs, pyqrcode
from binascii import hexlify
from pyqrcode import QRCode 


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

        pbks = stub.ListChannels(ln.ListChannelsRequest(), metadata=[('macaroon', macaroon)])
        pubkey_list = [str(i.remote_pubkey) for i in pbks.channels]

        response = stub.ListPeers(ln.ListPeersRequest(), metadata=[('macaroon', macaroon)])
        show_current_peers = response.peers
        show_current_peers_list = []
        for peer in show_current_peers:
            if peer.pub_key in pubkey_list:
              show_current_peers_list.append((str(peer.pub_key), True))
            else:
              show_current_peers_list.append((str(peer.pub_key), False))
        conn = True
        length_of = len(show_current_peers_list)

    except:
        show_current_peers_list = ["Offline!"]
        length_of = 0
        conn = False
        pubkey_list = ["Offline!"]

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
               show_current_peers_list.append((nodeid, False))
               length_of = len(show_current_peers_list)
               result = "Successfully connected!"
               return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="SuccessCon", conn=conn)
            except:
               return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseCon", conn=conn)
          else:
            return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseCon", conn=conn)
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
                return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="SuccessDis", conn=conn)
            except:
                return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseDis", conn=conn)
          else:
            return render_template('peerpage.html', len=len(show_current_peers_list), show_current_peers=show_current_peers_list, length_of=length_of, result="FalseDis", conn=conn)
    return render_template('peerpage.html', len=len(show_current_peers_list), length_of=length_of, show_current_peers=show_current_peers_list, conn=conn)               

@app.route('/channels', methods=['GET', 'POST'])
def channelpage():
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

        response = stub.ListChannels(ln.ListChannelsRequest(), metadata=[('macaroon', macaroon)])
        walbal = stub.WalletBalance(ln.WalletBalanceRequest(), metadata=[('macaroon', macaroon)])
        availablefunds = walbal.confirmed_balance
        channellist = response.channels
        closedchannelidentifiers = []
        channelidentifiers = []
        pendingchannelidentifiers = []

        pendingresponse = stub.PendingChannels(ln.PendingChannelsRequest(), metadata=[('macaroon', macaroon)])
        pend = pendingresponse.pending_open_channels
        for i in pend:
          k = ((str(i.channel.remote_node_pub)), str(i.channel.channel_point), int(i.channel.capacity), int(i.channel.local_balance))
          pendingchannelidentifiers.append(k)
        length_of_pending = len(pendingchannelidentifiers)

        closedresponse = stub.ClosedChannels(ln.ClosedChannelsRequest(), metadata=[('macaroon', macaroon)])
        for i in closedresponse.channels:
         p = (str(i.remote_pubkey), str(i.channel_point), int(i.capacity), int(i.close_height), int(i.settled_balance))
         closedchannelidentifiers.append(p)
        length_of_closed = len(closedchannelidentifiers)

        for i in channellist:
         if i.active == True:
          k = (str(i.remote_pubkey), int(i.capacity), int(i.local_balance), int(i.remote_balance), int(i.commit_fee), str(i.channel_point))
          channelidentifiers.append(k)
        conn = True
        length_of = len(channelidentifiers)
        try:
         outcap = sum(zip(*channelidentifiers)[2])
         incap = sum(zip(*channelidentifiers)[3])
        except:
         outcap = incap = 0
         length_of = 0


    except:
        conn = False

    if conn == True:
      if request.method == "POST":
        if request.form['action'] == "openchan":
              try:
                pkstring = str(request.form['channelpubkey'])
                locfundamt = int(request.form['channelamt'])
                response = stub.OpenChannelSync(ln.OpenChannelRequest(node_pubkey_string=pkstring, local_funding_amount=locfundamt, push_sat=0), metadata=[('macaroon', macaroon)])
                if response.funding_txid_bytes:
                  return render_template('channels.html', availablefunds=availablefunds, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers,
                   outcap=outcap, incap=incap, conn=conn, opened="True", length_of=length_of, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)   
              except:
                return render_template('channels.html', availablefunds=availablefunds, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers,
                   outcap=outcap, incap=incap, conn=conn, opened="True", length_of=length_of, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)
        elif request.form['action'] == "closechan":
              try:
                return ln.ChannelPoint(funding_txid_string=str(request.form['channelpubkey']))
                stub.CloseChannel(ln.CloseChannelRequest(channel_point=channelpoint), metadata=[('macaroon', macaroon)])
                return render_template('channels.html', availablefunds=availablefunds, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers,
                 outcap=outcap, incap=incap, conn=conn, closed="pendclose", length_of=length_of, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)
              except:
                return render_template('channels.html', availablefunds=availablefunds, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers,
                 outcap=outcap, incap=incap, conn=conn, closed="couldntclose", length_of=length_of, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)
        elif request.form['action'] == "fclosechan":
              try:
                return ln.ChannelPoint(funding_txid_string=str(request.form['channelpubkey']))
                stub.CloseChannel(ln.CloseChannelRequest(channel_point=channelpoint, force=True), metadata=[('macaroon', macaroon)])
                return render_template('channels.html', availablefunds=availablefunds, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers,
                 outcap=outcap, incap=incap, conn=conn, closed="pendclose", length_of=length_of, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)
              except:
                return render_template('channels.html', availablefunds=availablefunds, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers,
                 outcap=outcap, incap=incap, conn=conn, closed="couldntclose", length_of=length_of, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)
      else:
        return render_template('channels.html', conn=conn, length_of=length_of, channelidentifiers=channelidentifiers, closedchannelidentifiers=closedchannelidentifiers, incap=incap,
     outcap=outcap, availablefunds=availablefunds, length_of_closed=length_of_closed, pendingchannelidentifiers=pendingchannelidentifiers, length_of_pending=length_of_pending)

    return render_template('channels.html', conn=conn, length_of=0, channelidentifiers=0, closedchannelidentifiers=0, incap=0,
     outcap=0, availablefunds=0, length_of_closed=0, pendingchannelidentifiers=0, length_of_pending=0)

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

        newaddress = rpc_connect.getnewaddress()
        packqraddr = pyqrcode.create(newaddress)
        packqraddr.svg("app/static/img/newaddress.svg", scale=8)

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

      lninvoice = (stub.AddInvoice(ln.Invoice(), metadata=[('macaroon', macaroon)])).payment_request
      packlnaddr = pyqrcode.create(lninvoice)
      packqraddr.svg("app/static/img/lninvoice.svg", scale=8)

     except:
      offchain_balance = "Offline!"

     if conn == True:
      if request.method == 'POST':
        if request.form['action'] == "sendbutton":
          if request.form['fee'] == "medfee":
            try:
              txid = rpc_connect.sendtoaddress(request.form['address'], request.form['amt'], "", "", False, True, medtx['blocks'])

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=True, txid=txid, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
            except:

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)

          elif request.form['fee'] == "highfee":
            try:
              txid = rpc_connect.sendtoaddress(request.form['address'], request.form['amt'], "", "", False, True, fasttx['blocks'])

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=True, txid=txid, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
            except:

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice) 
          elif request.form['fee'] == "lowfee":
            try:
              txid = rpc_connect.sendtoaddress(request.form['address'], request.form['amt'], "", "", False, True, slowtx['blocks'])

              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=True, txid=txid, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
            except:
              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)

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
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", req_desc=req_desc, req_amt=req_amt, req_to=req_to, switch=True, offchain_balance=offchain_balance, req_whole=req_whole, newaddress=newaddress, lninvoice=lninvoice)
              else:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", switch=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
            except:
              return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", switch=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
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
                 return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance, successln=False, error=result.payment_error, newaddress=newaddress, lninvoice=lninvoice)
               else:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance, successln=True, preimage=hexlify(result.payment_preimage), newaddress=newaddress, lninvoice=lninvoice)
              except:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
            except:
                return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx=False, offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
        
      else:
        return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance, newaddress=newaddress, lninvoice=lninvoice)
     return render_template('makepayment.html', onchain_balance=onchain_balance, fasttxrate=fasttxrate, medtxrate=medtxrate, slowtxrate=slowtxrate, successfultx="N/A", offchain_balance=offchain_balance)

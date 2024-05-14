import Crypto
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import binascii
import flask
from flask import request, render_template

class Transaction:
    def __init__(self, senderAddress, senderPrivateKey, recipient, amount):
        self.senderAddress = senderAddress
        self.senderPrivateKey = senderPrivateKey
        self.recipient = recipient
        self.amount = amount

    def to_dict(self):
        return {'Sender':self.senderAddress, 'Recipient' : self.recipient, 'Amount' : self.amount}

    def signTransaction(self):
        privateKey = RSA.importKey(binascii.unhexlify(self.senderPrivateKey))
        signee = PKCS1_v1_5.new(privateKey)
        senderSHA = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.unhexlify(signee.sign(senderSHA)).decode('ascii')

appClient = flask.Flask(__name__)

@appClient.route('/')
def index():
    return render_template('./index.html')

@appClient.route('/make/transaction')
def makeTransaction():
    # TODO
    pass

@appClient.route('/view/transactions')
def viewTransaction():
    # TODO
    pass

@appClient.route('/wallet/new', methods=['GET'])
def newWallet():
    randomBytes = Crypto.Random.new().read
    privateKey = RSA.generate(1024, randomBytes)
    publicKey = privateKey.publickey()
    response = {'Private_Key' : binascii.hexlify(privateKey.exportKey(format='DER')).decode('ascii'),
                'Public_Key' : binascii.hexlify(publicKey.exportKey(format='DER')).decode('ascii'),}
    return flask.jsonify(response), 200

@appClient.route('/generate/transaction', methods=['POST'])
def generateTransaction():
    # senderAddress = request.form['senderAddress']
    # senderPrivateKey = request.form['senderPrivateKey']
    # recipient = request.form['recipient']
    # amount = request.form['amount']
    values = flask.request.get_json()
    senderAddress = values['senderAddress']
    senderPrivateKey = values['senderPrivateKey']
    recipient = values['recipient']
    amount = values['amount']

    newTransaction = Transaction(senderAddress, senderPrivateKey, recipient, amount)

    response = {'Transaction' : newTransaction.to_dict(), 'signature' : newTransaction.signTransaction()}
    return flask.jsonify(response), 200

if __name__ == '__main__':
    appClient.run()
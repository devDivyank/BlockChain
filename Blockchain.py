import binascii
import hashlib
import json
import time
import urllib.parse
from uuid import uuid4
import flask
import requests
import Crypto
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random

nodeID = str(uuid4()).replace('-', '')

class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.addNewBlock(100, 1)
        self.nodes = set()
        self.nodeID = str(uuid4()).replace('-', '')

    def addNewBlock(self, proof, previousHash = None):
        newBlock = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.transactions,
            'proof': proof,
            'previousHash': previousHash or self.hash(self.chain[-1]),
        }
        self.chain.append(newBlock)
        self.transactions = []
        return newBlock

    def addNewTransaction(self, sender, recipient, amount, signature):
        # self.transactions.append({'sender':sender, 'recipient':recipient, 'amount':amount})
        # return self.lastBlock['index'] + 1
        transaction = {'sender':sender, 'recipient':recipient, 'amount':amount}
        if sender == 0:
            self.transactions.append(transaction)
            return self.lastBlock['index'] + 1
        else:
            verification = self.verifyTransaction(sender, signature, transaction)
            if verification:
                self.transactions.append(transaction)
                return self.lastBlock['index'] + 1
            else:
                return False

    def verifyTransaction(self, sender, signature, transaction):
        publicKey = RSA.importKey(binascii.unhexlify(sender))
        verifier = PKCS1_v1_5.new(publicKey)
        senderSHA = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(senderSHA, binascii.unhexlify(signature))

    def registerNode(self, nodeAddress: str):
        urlAddress = urllib.parse.urlparse(nodeAddress)
        try:
            self.nodes.add(urlAddress.netloc)
        except:
            return "Invalid node address."

    def validChain(self, chain):
        lastBlock = chain[0]
        currentIndex = 1
        while currentIndex < len(chain):
            currentBlock = chain[currentIndex]
            # print(f'{lastBlock}')
            # print(f'{currentBlock}')
            # print("\n------------------\n")
            if currentBlock['prevHash'] != self.hash(lastBlock):
                return False

            ### TODO : REMOVE REWARD TRANSACTION OR NOT???

            if not self.proofValidity(lastBlock['proof'], currentBlock['proof']):
                return False
            lastBlock = currentBlock
            currentIndex += 1
        return True

    def resolveConflict(self):
        allNodes = self.nodes
        newChain = None
        maxLength = len(self.chain)

        for node in allNodes:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > maxLength and self.validChain(chain):
                    maxLength = length
                    newChain = chain

        if newChain:
            self.chain = newChain
            return True
        return False

    @staticmethod
    def hash(block):
        blockJSON = json.dumps(str(block), sort_keys=True).encode()
        return hashlib.sha256(blockJSON).hexdigest()

    @property
    def lastBlock(self):
        return self.chain[-1]

    def proofOfWork(self, lastProof):
        proof = 0
        while not self.proofValidity(lastProof, proof):
            proof += 1
        return proof

    def proofValidity(self, lastProof, proof):
        guessVal = f'{lastProof}{proof}'.encode()
        guessValHash = hashlib.sha256(guessVal).hexdigest()
        return guessValHash[:4] == "0000"

myApp = flask.Flask(__name__)
blockChain = Blockchain()

@myApp.route('/')
def index():
    # TODO
    pass

@myApp.route('/configure')
def configure():
    # TODO
    pass

@myApp.route('/mine', methods=['GET'])
def mine():
    lastBlock = blockChain.lastBlock
    lastProof = lastBlock['proof']
    proof = blockChain.proofOfWork(lastProof)

    # rewardTransaction for mining
    blockChain.addNewTransaction(0, blockChain.nodeID, 1, "")

    previousHash = blockChain.hash(lastBlock)
    newBlock = blockChain.addNewBlock(proof, previousHash)

    messageToUser = {'message' : 'New block mined!',
                     'index' : newBlock['index'],
                     'transactions' : newBlock['transactions'],
                     'proof' : newBlock['proof'],
                     'previousHash' : newBlock['previousHash']}

    return flask.jsonify(messageToUser), 200

@myApp.route('/transactions/new', methods=['POST'])
def newTransaction():
    values = flask.request.get_json()
    requiredValues = ['sender', 'recipient', 'amount', 'signature']
    if not all(v in values for v in requiredValues):
        return 'Data for transaction is missing.', 400

    transactionSatus = blockChain.addNewTransaction(values['sender'], values['recipient'], values['amount'], values['signature'])
    if transactionSatus == False:
        messageToUser = {'message': f'Transaction could not be completed!'}
        return flask.jsonify(messageToUser), 406
    else:
        messageToUser = {'message': f'Transaction will be added to block {index}'}
        return flask.jsonify(messageToUser), 201

@myApp.route('/transactions/get', methods=['GET'])
def getTransactions():
    response = {'Transactions' : blockChain.transactions}
    return flask.jsonify(response), 200

@myApp.route('/chain', methods=['GET'])
def fullChain():
    response = {'chain':blockChain.chain, 'length':len(blockChain.chain)}
    return flask.jsonify(response), 200

@myApp.route('/nodes/register', methods=['POST'])
def registerNodes():
    values = flask.request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "No nodes to add to network."
    for nodeID in nodes:
        blockChain.registerNode(nodeID)
    messageToUser = { 'message': 'New node(s) added!)',
                      'All node(s) currently in network': list(blockChain.nodes) }
    return flask.jsonify(messageToUser), 201

@myApp.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockChain.resolveConflict()
    if replaced:
        messageToUser = { 'Message' : 'Replaced with the longest chain on the network.',
                          'New Chain' : blockChain.chain}
    else:
        messageToUser = {'Message': 'Your chain is authoritative. (longest chain on network)',
                         'New Chain': blockChain.chain}
    return flask.jsonify(messageToUser), 200

@myApp.route('/nodes/get', methods=['GET'])
def allNodes():
    nodes = list(blockChain.nodes)
    response = {'Nodes':nodes}
    return flask.jsonify(response), 200


if __name__ == '__main__':
    myApp.run()
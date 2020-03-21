import requests
import time
import hashlib
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from urllib.parse import urlparse
from collections import OrderedDict
import binascii


class BlockObject:

	def __init__(self, block_number, timestamp, transactions, nonce, previous_hash, proof_number):
		self.block_number = block_number
		self.timestamp = timestamp
		self.transactions = transactions
		self.nonce = nonce
		self.previous_hash = previous_hash
		self.proof_number = proof_number


class TransactionObject:

	def __init__(self, address_sender, sender_private_key, address_recipient, amount):
		"""4 pieces of information that a sender needs to create a transaction"""
		self.address_sender = address_sender
		self.sender_private_key = sender_private_key
		self.address_recipient = address_recipient
		self.amount = amount

	def to_dict(self):
		"""
		Returns the transaction information in a Python dictionary format without the 
		senders private key.
		"""
		return OrderedDict({'address_sender': self.address_sender,
							'address_recipient': self.address_recipient,
							'amount': self.amount})

	def sign_transaction(self):
		"""
		Takes the transaction information (without the senders private key)
		and signs it using the senders private key.
		Sign transaction with private key
		"""
		print(self.sender_private_key)
		private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
		signer = PKCS1_v1_5.new(private_key)
		h = SHA.new(str(self.to_dict()).encode('utf8'))
		return binascii.hexlify(signer.sign(h)).decode('ascii')

class BlockchainObject:

	def __init__(self):
		self.chain = list()
		self.transactions = list()
		self.nodes = set()
		self.transaction_data = list()
		self.build_genesis()

	def add_node(self, node_url):
		url_parsed = urlparse(node_url)
		if url_parsed.netloc:
			self.nodes.add(url_parsed.netloc)
		elif url_parsed.path:
			self.nodes.add(url_parsed.path)
		else:
			raise ValueError('Invalid URL')

	def build_genesis(self):
		self.create_block(0, '00', 1)

	def create_block(self, nonce, previous_hash, proof_number):
		block = BlockObject(len(self.chain), time.time(), self.transactions, nonce, previous_hash, proof_number)
		self.transactions = list()
		self.chain.append(block)
		return block

	def hash(self, block):
		"""SHA-256 of string: 'block_numberproof_numberprevious_hashtransaction_datatimestamp' """
		block_string = "{}{}{}{}{}".format(block.block_number, block.proof_number, block.previous_hash, self.transaction_data, block.timestamp)
		return hashlib.sha256(block_string.encode()).hexdigest()

	def proof_of_work(self):
		last_block = self.chain[-1]
		last_hash = self.hash(last_block)
		nonce = 0
		while not self.check_validity_proof(self.transaction, last_hash, nonce):
			"""While the first N digits (dependent of the difficulty) of the 
			hash_guess arent equal to all 0's add 1 to nonce. The proof is obtained by increasing the nonce."""
			nonce += 1
		return nonce

	def check_validity_proof(self, transactions, last_block_hash, nonce, difficulty):
		"""True si es que n=difficulty primeros elementos del hash son 0's"""
		guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
		hash_guess = hashlib.sha256(guess).hexdigest()
		return hash_guess[:difficulty] == '0'*difficulty

	def submit_transaction(self, address_sender, address_receptor, amount, signature):
		transaction = {'address_sender': address_sender, 'address_receptor': address_receptor, 'amount': amount}
		#Reward for mining a block
		"""AQUÍ: QUE ES MINING_SENDER??
		Si el minero es el que hace el submit?"""
		if address_sender == MINING_SENDER:
			self.transactions.append(transaction)
			return len(self.chain) + 1
		#Manages transactions from wallet to another wallet
		else:
			transaction_verification = self.verify_transaction_signature(address_sender, signature, transaction)
			if transaction_verification:
				self.transactions.append(transaction)
				return len(self.chain) + 1
			else:
				return False

	def resolve_conflicts(self):
		"""
		CONSENSUS

		Resolve conflicts between blockchain's nodes
		by replacing our chain with the longest one in the network.
		"""
		neighbours = self.nodes
		new_chain = None
		max_length = len(self.chain)
		# Grab and verify the chains from all the nodes in our network
		for node in neighbours:
			print('http://' + node + '/chain')
			response = requests.get('http://' + node + '/chain')
			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				# Check if the length is longer and the chain is valid
				if length > max_length and self.check_validity_chain(chain):
					max_length = length
					new_chain = chain

		# Replace our chain if we discovered a new, valid chain longer than ours
		if new_chain:
			self.chain = new_chain
			return True

		return False

	def check_validity_chain(self, chain):
		first_block = chain[0]
		index = 1
		while index < len(chain):
			block = chain[index]
			if block['previous_hash'] != self.hash(last_block):
				return False
			transactions = block.transactions[:-1]

	def verify_transaction_signature(self, address_sender, signature, transaction): 
		public_key = RSA.importKey(binascii.unhexlify(address_sender))
		verifier = PKCS1_v1_5.new(public_key)
		h = SHA.new(str(transaction).encode('utf8'))
		return verifier.verify(h, binascii.unhexlify(signature))




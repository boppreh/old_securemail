class Key(object):
    """
    Interface for encryption keys, symmetric or not.
    """
    def encrypt(self, message):
        raise NotImplementedError()

    def decrypt(self, message):
        raise NotImplementedError()

    def serialize(self):
        raise NotImplementedError()

    def load(self, string):
        raise NotImplementedError()
    
class Network(object):
    """
    Interface for Network objects. These objects are used to send and receive
    messages from an arbitrary network.
    """
    def register(self, address, entity):
        raise NotImplementedError()

    def send(self, address, message):
        raise NotImplementedError()

class Client(object):
    """
    Secure mail client, storing its own address and key pair internally.
    Messages are sent through the given Network object.
    """
    def __init__(self, address, privkey, pubkey, network):
        """
        Creates a new Client instance. `address` is the global address of this
        instance, `privkey` and `pubkey` are its keypair, and `network` is used
        to send and receive messages.
        """
        self.address = address
        self.privkey = privkey
        self.pubkey = pubkey
        self.pubkey_cache = {}
        self.network = network
        self.message_buffer = []

        self.network.register(address, self)

    def _get_address_pubkey(self, address):
        """
        Returns the associated public key of a given address.
        """
        if not address in self.pubkey_cache:
            self.network.send(address, self.address + '\n' + self.pubkey.serialize() + '\nsend me your pubkey')
        return self.pubkey_cache[address]

    def receive_raw(self, message):
        """
        Signals this client that it has received a message.
        """
        sender, pubkey_str, text = message.split('\n', 2)
        pubkey = self.pubkey.load(pubkey_str)
        self.pubkey_cache[sender] = pubkey

        if text == 'send me your pubkey':
            self.network.send(sender, self.address + '\n' + self.pubkey.serialize() + '\n')
        elif len(text):
            self.message_buffer.append(pubkey.decrypt(self.privkey.decrypt(text)))

    def receive(self):
        """
        Returns a message from the message buffer or wait for one to arrive.
        """
        return self.message_buffer.pop(0)

    def send(self, address, message):
        """
        Sends a secure message to a given address.
        """
        pubkey = self._get_address_pubkey(address)
        ciphertext = pubkey.encrypt(self.privkey.encrypt(message))
        self.network.send(address, self.address + '\n' + self.pubkey.serialize() + '\n' + ciphertext)

if __name__ == '__main__':
    alice = Client('alice', MockKey('a', True), MockKey('a', False), IntervalNetwork)
    bob = Client('bob', MockKey('b', True), MockKey('b', False), IntervalNetwork)

    register_mail('alice', alice)
    register_mail('bob', bob)

    bob.send('alice', 'attack at dawn')

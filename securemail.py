class InternalNetwork(object):
    def __init__(self):
        self.entities = {}

    def register(self, name, entity):
        print('Registered {}'.format(name))
        self.entities[name] = entity

    def send(self, name, message):
        print('to: {}. "{}"\n'.format(name, message))
        self.entities[name].receive_raw(message)

class Client(object):
    def __init__(self, address, privkey, pubkey, network):
        self.address = address
        self.privkey = privkey
        self.pubkey = pubkey
        self.pubkey_cache = {}
        self.network = network
        self.message_buffer = []

        self.network.register(address, self)

    def _get_address_pubkey(self, address):
        if not address in self.pubkey_cache:
            self.network.send(address, self.address + '\n' + self.pubkey.serialize() + '\nsend me your pubkey')
        return self.pubkey_cache[address]

    def receive_raw(self, message):
        sender, pubkey_str, text = message.split('\n', 2)
        pubkey = self.pubkey.load(pubkey_str)
        self.pubkey_cache[sender] = pubkey

        if text == 'send me your pubkey':
            self.network.send(sender, self.address + '\n' + self.pubkey.serialize() + '\n')
        elif len(text):
            self.message_buffer.append(pubkey.decrypt(self.privkey.decrypt(text)))

    def receive(self):
        return self.message_buffer.pop(0)

    def send(self, address, message):
        pubkey = self._get_address_pubkey(address)
        ciphertext = pubkey.encrypt(self.privkey.encrypt(message))
        self.network.send(address, self.address + '\n' + self.pubkey.serialize() + '\n' + ciphertext)

if __name__ == '__main__':
    alice = Client('alice', MockKey('a', True), MockKey('a', False), IntervalNetwork)
    bob = Client('bob', MockKey('b', True), MockKey('b', False), IntervalNetwork)

    register_mail('alice', alice)
    register_mail('bob', bob)

    bob.send('alice', 'attack at dawn')

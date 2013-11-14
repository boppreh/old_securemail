entities = {}

def register_mail(name, entity):
    print('Registered {}'.format(name))
    entities[name] = entity

def send_mail(name, message):
    print('to: {}. "{}"\n'.format(name, message))
    entities[name].receive(message)

class MockKey(object):
    def __init__(self, char, is_private):
        self.char = char
        self.is_private = is_private

    def encrypt(self, message):
        return self.char + ('-' if self.is_private else '+') + message

    def decrypt(self, message):
        assert message[0] == self.char, 'Message should start with {}, not {} ({}).'.format(self.char, message[0], message)
        expected_symbol = ('+' if self.is_private else '-')
        assert message[1] == expected_symbol, 'Message should start be {}, not {} ({}).'.format(self.char, message[0], message)
        return message[2:]

    def serialize(self):
        return self.encrypt('')

    @staticmethod
    def load(string):
        return MockKey(string[0], string[1] == '-')

class TrustedServer(object):
    def __init__(self, privkey, pubkey):
        self.privkey = privkey
        self.pubkey = pubkey

class Client(object):
    def __init__(self, address, privkey, pubkey, trusted_root):
        self.address = address
        self.privkey = privkey
        self.pubkey = pubkey
        self.trusted_root = trusted_root
        self.pubkey_cache = {}

    def _get_address_pubkey(self, address):
        if not address in self.pubkey_cache:
            send_mail(address, self.address + '\n' + self.pubkey.serialize() + '\nsend me your pubkey')
        return self.pubkey_cache[address]

    def receive(self, message):
        sender, pubkey_str, text = message.split('\n', 2)
        pubkey = MockKey.load(pubkey_str)
        self.pubkey_cache[sender] = pubkey

        if text == 'send me your pubkey':
            send_mail(sender, self.address + '\n' + self.pubkey.serialize() + '\n')
        elif len(text):
            print('Received:', pubkey.decrypt(self.privkey.decrypt(text)))

    def send(self, address, message):
        pubkey = self._get_address_pubkey(address)
        ciphertext = pubkey.encrypt(self.privkey.encrypt(message))
        send_mail(address, self.address + '\n' + self.pubkey.serialize() + '\n' + ciphertext)

if __name__ == '__main__':
    #root = TrustedServer(MockKey('r', True), MockKey('r', False))
    
    alice = Client('alice', MockKey('a', True), MockKey('a', False), root)
    bob = Client('bob', MockKey('b', True), MockKey('b', False), root)

    register_mail('alice', alice)
    register_mail('bob', bob)

    bob.send('alice', 'attack at dawn')

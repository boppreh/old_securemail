import unittest
from securemail import Client, InternalNetwork

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

    def load(self, string):
        return MockKey(string[0], string[1] == '-')

class TestClient(unittest.TestCase):
    def setUp(self):
        self.network = InternalNetwork()

    def make_client(self, name='alice'):
        address = name
        key_secret = name[0]
        return Client(address, MockKey(key_secret, True), MockKey(key_secret, False), self.network)

    def test_self_connection(self):
        c = self.make_client()
        c.send(c.address, 'message')
        self.assertEqual(c.receive(), 'message')

    def test_connection(self):
        c1 = self.make_client('alice')
        c2 = self.make_client('bob')
        c1.send(c2.address, 'message')
        self.assertEqual(c2.receive(), 'message')

if __name__ == '__main__':
    unittest.main()

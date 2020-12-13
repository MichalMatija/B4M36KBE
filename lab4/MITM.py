from lab4.Agent import Agent


class MITM:
    msg = None

    def __init__(self):
        self.alice = None
        self.bob = None

    def receive_public_data(self, p, g):
        if self.alice is None:
            self.alice = Agent()
            self.alice.receive_public_data(p, g)
        elif self.bob is None:
            self.bob = Agent()
            self.bob.receive_public_data(p, g)

    def send_public_data(self):
        if self.alice is not None:
            return self.alice.send_public_data()
        elif self.bob is not None:
            return self.bob.send_public_data()

    def receive_public_key(self, public_key):
        if self.alice.diffieHellman.shared_key is None:
            self.alice.receive_public_key(public_key)
        else:
            self.bob.receive_public_key(public_key)

    def send_public_key(self):
        if self.bob.diffieHellman.shared_key is None:
            return self.bob.send_public_key()
        else:
            return self.alice.send_public_key()

    def intercept_message(self, message):
        self.alice.receive_message(message)
        self.bob = self.msg = self.alice.msg
        return self.bob.send_message()
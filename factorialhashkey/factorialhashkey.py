import hashlib
import os

from factorialhashkey.exceptions import InvalidSignature, InvalidMessageHash

SIZE_TO_TEETH_RATIO = {
    8: 6,
    16: 9,
    24: 11,
    32: 13,
    40: 15,
    48: 17,
    56: 19,
    64: 21,
    72: 23,
    80: 25,
    88: 26,
    96: 28,
    104: 30,
    112: 31,
    120: 33,
    128: 35,
    136: 36,
    144: 38,
    152: 39,
    160: 41,
    168: 42,
    176: 44,
    184: 45,
    192: 47,
    200: 48,
    208: 49,
    216: 51,
    224: 52,
    232: 54,
    240: 55,
    248: 56,
    256: 58,
}


class FHK:
    def __init__(self, size, hash_algorithm=hashlib.shake_256):
        assert size % 8 == 0

        self.bytes = size // 8
        self.teeth = SIZE_TO_TEETH_RATIO[size]
        self.hash_algorithm = hash_algorithm

    def generate_key(self):
        return FHKPrivateKey(self)

    def get_hash_sign_iterations(self, message_hash):
        if len(message_hash) < self.teeth-1:
            raise InvalidMessageHash("Must be at lest {0} bytes long".format(self.teeth-1))

        key_positions = [i for i in range(self.teeth)]
        key_hash_iterations = [0 for _ in range(self.teeth)]

        for base, bb in zip(range(self.teeth, 1, -1), message_hash):
            idx = bb % base
            key_hash_iterations[key_positions[idx]] = base - 1
            del key_positions[idx]

        return key_hash_iterations

    def get_hash_sign_iterations_complement(self, message_hash):
        if len(message_hash) < self.teeth-1:
            raise InvalidMessageHash("Must be at lest {0} bytes long".format(self.teeth-1))

        key_positions = [i for i in range(self.teeth)]
        key_hash_iterations = self.get_hash_iterations_total()

        for base, bb in zip(range(self.teeth, 1, -1), message_hash):
            idx = bb % base
            key_hash_iterations[key_positions[idx]] = self.teeth - base
            del key_positions[idx]

        return key_hash_iterations

    def get_hash_iterations_total(self):
        return [self.teeth - 1 for _ in range(self.teeth)]

    def hash_key_parts(self, data, iterations, iteration_target=0):
        key_parts = []
        sk_o = self.hash_algorithm()

        for i in range(self.teeth):
            sp = i * self.bytes
            sk = data[sp:sp + self.bytes]
            if iteration_target:
                off_set = iteration_target - iterations[i]
            else:
                off_set = 0

            for r in range(iterations[i]):
                sk_m = sk_o.copy()
                sk_m.update(
                    sk[0:4] +
                    b"0" +
                    self.teeth.to_bytes(1, byteorder="big") +
                    i.to_bytes(1, byteorder="big") +
                    (off_set + r).to_bytes(1, byteorder="big") +
                    sk
                )
                # sk_m.update(sk)
                sk = sk_m.digest(self.bytes)

            key_parts.append(sk)

        return b"".join(key_parts)

    def derive_public_key(self, signature, message_hash):
        return self.hash_key_parts(
            signature,
            self.get_hash_sign_iterations_complement(message_hash),
            iteration_target=self.teeth - 1
        )


class FHKPrivateKey:
    def __init__(self, fhk: FHK, data=None):
        self.fhk = fhk
        if data:
            self._data = data
        else:
            self._data = os.urandom(fhk.bytes * 2)

    def private_key(self):
        return self._data

    def private_keys(self):
        m = self.fhk.hash_algorithm()
        m.update(self._data)

        secret_bytes = m.digest(
            self.fhk.teeth * self.fhk.bytes
        )

        return secret_bytes

    def public_key(self):
        secret_bytes = self.private_keys()

        public_key = self.fhk.hash_key_parts(
            secret_bytes,
            self.fhk.get_hash_iterations_total()
        )

        return FHKPublicKey(self.fhk, public_key)

    def sign(self, message_hash):
        secret_bytes = self.private_keys()

        return self.fhk.hash_key_parts(
            secret_bytes,
            self.fhk.get_hash_sign_iterations(message_hash)
        )


class FHKPublicKey:
    def __init__(self, fhk: FHK, data):
        self.algo = fhk
        self._data = data

    def verify(self, signature, message_hash):
        public_bytes = self._data

        if not self.algo.derive_public_key(signature, message_hash) == public_bytes:
            raise InvalidSignature()

from factorialhashkey import FHK
import hashlib


def test_factorial_hashkey_signature():
    private_key = FHK(
        size=120
    ).generate_key()

    public_key = private_key.public_key()

    print(public_key._data)
    message = b"Hola"
    message_hash = hashlib.shake_256(message).digest(32)

    h_r = private_key.fhk.get_hash_sign_iterations(message_hash)
    hrc = private_key.fhk.get_hash_sign_iterations_complement(message_hash)

    print(h_r)
    print(hrc)

    for i in range(private_key.fhk.teeth):
        assert h_r[i] + hrc[i] == private_key.fhk.teeth - 1

    signature = private_key.sign(message_hash)

    for i in range(1000):
        public_key.verify(signature, message_hash=message_hash)

    # print(signature)

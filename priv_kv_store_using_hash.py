from hashlib import pbkdf2_hmac
import os
import zlib

"""This approach is clearly less useful than polynomial
interpolation-based approach in priv_kv_store.py"""
_B = 32//8  ## representation size of the keys
CTX_SIZE = 1024//8   ## representation size of the values
N_FIXED_VALUES = int(2**15)  ## Max #points to fix in kv store

def hash_to(r, nb, k):
    return hash(r + k) % nb

def prg(seed, n):
    return pbkdf2_hmac('sha256', seed, b'', 1, dklen=n)

def xor(a, b):
    return (int.from_bytes(a, 'little') ^ int.from_bytes(b, 'little'))\
        .to_bytes(len(a), 'little')

def enc(k, j, m):
    iv = j.to_bytes(8, 'little')
    return xor(prg(iv + k, len(m)), m)

def dec(k, j, c):
    iv = j.to_bytes(8, 'little')
    return xor(prg(iv + k, len(c)), c)

class PrivKeyValueStore_hash(object):
    def __init__(self, d=None):
        """Assume keys are all smaller than 128-bit, and values are 1024-bit"""
        if d is None:
            return
        self.r, self.D = self.fill_values(d)
        
    def fill_values(self, d):
        nb = 3*N_FIXED_VALUES
        D = [None for _ in range(nb)]
        ntry = 0
        while ntry<5:
            failed = False
            r = os.urandom(8)
            jset = {}
            for k in d.keys():
                j = hash_to(r, nb, k)
                if j in jset:
                    print(f"Index Collision!! Retrying: {ntry}")
                    failed = True
                    break
                jset[k] = j
            if not failed:
                break
            if failed:
                raise ("Abort, could not create a fixed hash bucket")
            ntry += 1

        for k, v in d.items():
            j = jset[k]
            print(f"insert: {k} --> {j}")
            D[j] = enc(k, j, v)
            
        for i in range(len(D)):
            if not D[i]:
                D[i] = os.urandom(CTX_SIZE)

        assert len(D) == nb, f"nb={nb}, len(D) = {len(D)}"
        return r, D

    def serialize(self, compressed=False):
        s = self.r + b''.join(self.D)
        if compressed:
            return zlib.compress(s, 3)
        else:
            return s
    
    def deserialize(self, s, compressed=False):
        if compressed:
            s = zlib.decompress(s)
        self.r = s[:8]; s = s[8:]
        self.D = [
            s[i:i+CTX_SIZE] for i in range(0, len(s), CTX_SIZE)
        ]
        nb = len(self.D)

    def query(self, k):
        nb = len(self.D)
        j = hash_to(self.r, nb, k)
        print(f"query: {k} --> {j}")
        return dec(k, j, self.D[j])


def test_enc():
    for i in range(1000):
        n = int.from_bytes(os.urandom(1), 'little') + 10
        s = os.urandom(n);
        k = os.urandom(16)
        c = enc(k, s)
        sprime = dec(k, c)
        s2 = dec(b'a'*16, c)
        assert s == sprime
        assert s != s2, f"n={n}, s={s}, k = {k}"
    print("All enc and dec is successful")
    
def test_serialize():
    pkv = PrivKeyValueStore_hash({})
    s = pkv.serialize()
    qkv = PrivKeyValueStore_hash()
    qkv.deserialize(s)
    assert qkv.D == pkv.D, f"{qkv.D[0]}\n{pkv.D[0]}"
    print("All tests passed")

def test_kv():
    d = {
        b'a'*_B: b'1'*CTX_SIZE,
        b'b'*_B: b'2'*CTX_SIZE,
        b'c'*_B: b'3'*CTX_SIZE,
        b'd'*_B: b'4'*CTX_SIZE,
    }
    pkv = PrivKeyValueStore_hash(d)
    s = pkv.serialize()
    qkv = PrivKeyValueStore_hash()
    qkv.deserialize(s)
    for i, (a,b) in enumerate(zip(qkv.D, pkv.D)):
        assert a == b, f"{i}\n{a}\n{b}"
    for k, v in d.items():
        v1 = qkv.query(k)
        v2 = pkv.query(k)
        assert v1 == v, f"Basic failed: {k} = {v}, but retrived: {v1}"
        assert v2 == v, f"Serialization failed: {k} = {v}, but retrived: {v1}"

    print("All tests passed")
    


if __name__ == "__main__":
    # test_enc()
    # test_serialize()
    test_kv()

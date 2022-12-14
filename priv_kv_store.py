import time
s = time.time()
import galois
import numpy as np
import math
import os
import zlib
e = time.time()
print(f"All libraries loaded in {e-s}"); s = e

""" This program allows creating a polynomial in the integer field
that passes through a fixed @N_FIXED_VALUES points.  The polynomial
is defined over large prime field (aka Galois field).  The keys must
be element of this field. Values must be of size CTX_SIZE or smaller.

This way we can send @N_FIXED_VALUES to a recipient who can evaluate
the polynomial on any number of points, and will get the correct
values on the points the polynimal was programmed with. However, they
can't tell which of the points they evaluted the polynomial with are
are programmed values.

"""

_B = 128//8  ## representation size of the keys
CTX_SIZE = 1024//8   ## representation size of the values
N_FIXED_VALUES = 128  ## Max #points to fix in kv store

## Prime that will be used to define the prime field
## 2**64 - 59, 2**128 - 159, or 2**256 - 189 (Very slow!!)
LARGE_PRIME = galois.prev_prime(2**(_B*8))  
assert galois.is_prime(LARGE_PRIME)


G = galois.GF(LARGE_PRIME)
e = time.time()
print(f"Galois field creted in {e-s}"); s = e

def bytes_to_field_elems(s):
    assert isinstance(s, bytes) and len(s) <= CTX_SIZE, \
        f"type(s) = {type(s)}, len(s) = {len(s)}"
    n = math.ceil(len(s)/_B)
    s_arr = [
        G(int.from_bytes(s[i:i+_B], 'little'))
        for i in range(0, n*_B, _B)
    ]
    return s_arr

def elems_to_bytes(elems):
    assert len(elems) == math.ceil(CTX_SIZE/_B),\
        f'{len(elems)} != {CTX_SIZE/_B}'
    s = b''.join(e.to_bytes(_B, 'little') for e in elems)
    return s


class PrivKeyValueStore(object):
    def __init__(self, d=None):
        """Assume keys are all smaller than 128-bit, and values are 1024-bit"""
        if not d:
            return
        while len(d) < N_FIXED_VALUES:
            k = os.urandom(_B)
            v = os.urandom(CTX_SIZE)
            d[k] = v
        print(f"len(d) = {len(d)}")
        keys = list(d.keys())
        values = list(d.values())
        ## Assumption: Filed elements are always bigger than the key,
        ## if not hash the keys first.
        ks = [bytes_to_field_elems(e)[0] for e in keys]
        vals = list(zip(*[bytes_to_field_elems(e) for e in values]))
        s = time.time()
        print("Starting to create polynomials!")
        self.poly_arr = [
            PrivPoly(ks.copy(), list(vs))
            for vs in vals
        ]

    def serialize(self, compressed=False):
        n_poly_str = len(self.poly_arr).to_bytes(1, 'little')
        poly_str = b''.join(p.serialize() for p in self.poly_arr)
        s = n_poly_str + poly_str
        if compressed:
            return zlib.compress(s, 3)
        else:
            return s

    def deserialize(self, s, compressed=False):
        if compressed:
            s = zlib.decompress(s)
        n_poly = s[0]; s = s[1:]
        l = len(s)//n_poly
        self.poly_arr = [None for _ in range(n_poly)]
        for i in range(n_poly):
            self.poly_arr[i] = PrivPoly()
            self.poly_arr[i].deserialize(s[:l])
            s = s[l:]
        
    def query(self, key):
        ks = bytes_to_field_elems(key)[0]
        vs = [
            p._eval(ks).tolist()
            for p in self.poly_arr
        ]
        # print(f"vs = {vs} ({len(vs)})")
        return elems_to_bytes(vs)[:CTX_SIZE]

class PrivPoly(object):
    def __init__(self, keys=[], values=[]):
        global s
        if not keys:
            return
        assert len(keys) == len(values), f"keys and values are of different sizes, {len(keys)}, {len(values)}"
        assert len(keys) <= N_FIXED_VALUES, \
            f"Only {N_FIXED_VALUES} keys can be fixed, you sent {len(keys)} keys"
        assert all(x<LARGE_PRIME and y<LARGE_PRIME for (x,y) in zip(keys, values)), \
            "All values in keys array must be smaller than the field order." 
        if len(keys) < N_FIXED_VALUES:
            t_x_arr = G.Random(N_FIXED_VALUES - len(keys))
            t_y_arr = G.Random(N_FIXED_VALUES - len(keys))
            keys.extend(t_x_arr)
            values.extend(t_y_arr)
        self.poly = galois.lagrange_poly(G(keys), G(values))
        e = time.time()
        print(f"One lagrange interpolation done in {e-s}"); s = e


    def _eval(self, x):
        return self.poly(x)


    def repr(self):
        arr = [c.to_bytes(_B, 'little') for c in self.poly.coeffs.tolist()]
        return b''.join(arr)

    def load(self, s):
        assert len(s) == N_FIXED_VALUES * _B
        return G([int.from_bytes(s[i:i+_B], 'little')
                for i in range(0, len(s), _B)])

    def serialize(self):
        """ <size|1> || <order|size> | <num_coeffs|1> | <coeffs|num_coeffs*B>"""
        b = _B.to_bytes(1, 'little')
        order = G.order.to_bytes(_B, 'little')
        n_coeff = N_FIXED_VALUES.to_bytes(1, 'little')
        coeffs = self.repr()
        return b + order + n_coeff + coeffs

    def deserialize(self, s):
        global _B, N_FIXED_VALUES
        _B = s[0]; s = s[1:]
        order = int.from_bytes(s[:_B], 'little'); s = s[_B:]
        N_FIXED_VALUES = s[0];   s = s[1:]
        coeffs = self.load(s)
        # print("-->", coeffs)
        self.poly = galois.Poly(coeffs)
        

#----------- In-file TEST ---------------------------------------------
def test_privpoly():
    keys=[0, 12312, 123, 1, 9485857484, 9];
    values=[223, 3, 123844, 234234, 12123, 345346]
    p = PrivPoly(keys=keys, values=values)
    print(p.poly)
    s = p.serialize()
    # ------
    q = PrivPoly()
    q.deserialize(s)
    for k, v in zip(keys, values):
        assert q._eval(k) == v

from priv_kv_store_using_hash import PrivKeyValueStore_hash # Only for testing
def test_privkeyvaluestore(store):
    """store can be PrivKeyValueStore, or PrivKeyValueStore_hash"""
    print(f"\n-------- TESTING with {store} ---------------")
    keys=[c.to_bytes(_B, 'little')
          for c in [0, 12312, 123, 1, 94858574, 9]]
    values=[c.to_bytes(CTX_SIZE, 'little')
        for c in [223, 3, 123844, 234234, 12123, 345346]]
    pkv = store(dict(zip(keys, values)))
    for k, v in zip(keys, values):
        _v = pkv.query(k)
        # print(len(_v), len(v))
        assert _v == v, f"Expecting {k} =\n{v},\nbut got\n{_v}"
    
    print("---> Testing de/serialization")
    pkv_s = pkv.serialize(compressed=True)
    print(f"Size of the string to send for {N_FIXED_VALUES} keys is {len(pkv_s)}")
    qkv = store()
    qkv.deserialize(pkv_s, compressed=True)
    for k, v in zip(keys, values):
        _v = qkv.query(k)
        print(len(_v), len(v))
        assert _v == v, f"Expecting {k} =\n{v},\nbut got\n{_v}"

    print("---> randomness test")
    s = time.time()
    n = 10
    for i in range(n):
        k = os.urandom(_B)
        v = qkv.query(k)
        print(f"{k[:8]}: {v[:16]}")
    e = time.time()
    print(f"querying the funciton takes avg {(e-s)/n} sec"); s = e
    print("All tests are passed")

if __name__ == "__main__":
    # test_privpoly()
    test_privkeyvaluestore(PrivKeyValueStore)
    test_privkeyvaluestore(PrivKeyValueStore_hash)

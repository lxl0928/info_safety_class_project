def generate(self, bits, randfunc=None, progress_func=None,**kwargs):
    for i in (0, 1, 2, 3, 4, 5, 6, 7, 8):
        if bits == 512 + 64*i:
            return self._generate(bits, randfunc, progress_func, **kwargs)
    raise ValueError("Number of bits in p must be a multiple of 64 between 512 and 1024, not %d bits" % (bits,))


def _generate(self, bits, randfunc=None, progress_func=None, **kwargs):
    rf = self._get_randfunc(randfunc)
    obj = Crypto.PublicKey._DSA.generate_py(bits, rf, progress_func)    # TODO: Don't use legacy _DSA module
    if kwargs:
        obj.y = kwargs.get('y')
        obj.g = kwargs.get('g')
        obj.p = kwargs.get('p')
        obj.q = kwargs.get('q')
    key = self._math.dsa_construct(obj.y, obj.g, obj.p, obj.q, obj.x)
    return Crypto.PublicKey.DSA._DSAobj(self, key)


import Crypto.PublicKey.DSA
Crypto.PublicKey.DSA.DSAImplementation._generate = _generate
Crypto.PublicKey.DSA.DSAImplementation.generate = generate
Crypto.PublicKey.DSA._impl = Crypto.PublicKey.DSA.DSAImplementation()
Crypto.PublicKey.DSA.generate = Crypto.PublicKey.DSA._impl.generate
Crypto.PublicKey.DSA.construct = Crypto.PublicKey.DSA._impl.construct
Crypto.PublicKey.DSA.error = Crypto.PublicKey.DSA._impl.error


from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from Crypto.Random import random
import pickle


def encrypt(text, number=1024):
    key = DSA.generate(number)
    h = SHA.new(text).digest()
    k = random.StrongRandom().randint(1, key.q-1)
    r, s = key.sign(h, k)
    publickey = pickle.dumps(
        {"p": key.p, "q": key.q, "g": key.g, "y": key.y, "number": number}
    )
    privatekey = pickle.dumps({"x": key.x})
    signkey = pickle.dumps({"r": r, "s": s})
    return publickey, privatekey, signkey


def decode(text, signkey, publickey):
    try:
        publickey = pickle.loads(publickey)
        signkey = pickle.loads(signkey)
        h = SHA.new(text).digest()
        key = DSA.generate(
            publickey.get('number'),
            y=publickey.get('y'),
            g=publickey.get('g'),
            q=publickey.get('q'),
            p=publickey.get('p')
        )
        sig = (signkey.get('r'), signkey.get('s'))
        return key.verify(h, sig)
    except:
        return False

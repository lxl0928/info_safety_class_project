class _DSAKey(object):
    def size(self):
        return size(self.p) - 1

    def has_private(self):
        return hasattr(self, 'x')

    def _sign(self, m, k):
        if not self.has_private():
            raise TypeError("No private key")
        if not (1 < k < self.q):
            raise ValueError("k is not between 2 and q-1")
        inv_k = inverse(k, self.q)   # Compute k**-1 mod q
        r = pow(self.g, k, self.p) % self.q  # r = (g**k mod p) mod q
        s = (inv_k * (m + self.x * r)) % self.q
        return (r, s)

    def _verify(self, m, r, s):
        if not (0 < r < self.q) or not (0 < s < self.q):
            return False
        w = inverse(s, self.q)
        u1 = (m*w) % self.q
        u2 = (r*w) % self.q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p) % self.q
        return v == r

def dsa_construct(y, g, p, q, x=None):
    assert isinstance(y, int)
    assert isinstance(g, int)
    assert isinstance(p, int)
    assert isinstance(q, int)
    assert isinstance(x, (int, type(None)))
    obj = _DSAKey()
    obj.y = y
    obj.g = g
    obj.p = p
    obj.q = q
    if x is not None: obj.x = x
    return obj


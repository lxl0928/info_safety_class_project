# -*- coding: utf-8 -*-

"""RSA key生成代码.
新密钥用newkeys()函数创建。它会给你一个公钥PublicKey对象
和一个私钥PrivateKey对象。
"""

import logging

from rsa._compat import b, range
import rsa.prime
import rsa.pem
import rsa.common
import rsa.randnum
import rsa.core

__all__ = ['PublicKey', 'PrivateKey', 'newkeys']

log = logging.getLogger(__name__)
DEFAULT_EXPONENT = 65537

def find_p_q(nbits, getprime_func=rsa.prime.getprime, accurate=True):
    """返回两个nbits比特不同的素数的元组。
    所得 p * q 有exacty2 * nbits比特
    ：参数和nbits：位在每个p和q的数。
    ：参数getprime_func：在getprime功能，默认为
        ：PY：FUNC：`rsa.prime.getprime`。
    ：参数精确：是否启用精确模式与否。
    ：返回：（p, q），其中p>q
    """

    total_bits = nbits * 2

    #保证p和q相差不会太近,或者可以因子分解 
    # factor n.
    shift = nbits // 16
    pbits = nbits + shift
    qbits = nbits - shift

    #选择两个初始的素数 
    log.debug('find_p_q(%i): Finding p', nbits)
    p = getprime_func(pbits)
    log.debug('find_p_q(%i): Finding q', nbits)
    q = getprime_func(qbits)

    def is_acceptable(p, q):
        """Returns True iff p and q are acceptable:

            - p and q differ
            - (p * q) has the right nr of bits (when accurate=True)
        """

        if p == q:
            return False

        if not accurate:
            return True

        # Make sure we have just the right amount of bits
        found_size = rsa.common.bit_size(p * q)
        return total_bits == found_size

    # 一直选择素数直到符合要求.
    change_p = False
    while not is_acceptable(p, q):
        if change_p:
            p = getprime_func(pbits)
        else:
            q = getprime_func(qbits)

        change_p = not change_p

    # http://www.di-mgt.com.au/rsa_alg.html#crt
    return max(p, q), min(p, q)


def calculate_keys_custom_exponent(p, q, exponent):
    """计算的加密和解密密钥给定p，q和一个指数，
    并且将它们作为一个元组（E，D）
    ：参数q：第一个大质数
    ：参数p：第二大的质数
    ：参数指数：key指数 类型指数：INT
    """

    phi_n = (p - 1) * (q - 1)

    try:
        d = rsa.common.inverse(exponent, phi_n)
    except rsa.common.NotRelativePrimeError as ex:
        raise rsa.common.NotRelativePrimeError(
            exponent, phi_n, ex.d,
            msg="e (%d) and phi_n (%d) are not relatively prime (divider=%i)" %
                (exponent, phi_n, ex.d))

    if (exponent * d) % phi_n != 1:
        raise ValueError("e (%d) and d (%d) are not mult. inv. modulo "
                         "phi_n (%d)" % (exponent, d, phi_n))

    return exponent, d


def calculate_keys(p, q):
    """计算的加密和解密密钥给定p和q，和
    将它们作为一个元组（E，D）
    ：参数号码：第一个大素数
    ：参数问：第二大素数
    ：返回：元组（E，D）的加密和解密指数。
    """

    return calculate_keys_custom_exponent(p, q, DEFAULT_EXPONENT)


def gen_keys(nbits, getprime_func, accurate=True, exponent=DEFAULT_EXPONENT):
    """生成 n 位RSA密钥。返回（P，Q，E，D）。
    注意：这可能需要很长的时间，这取决于密钥的大小。
    ：参数nbits：p和q加起来就是总位数。``p``和
       ``q``都是``nbits/2``位。
    ：参数getprime_func：要么：PY：FUNC：`rsa.prime.getprime`或类似函数
    ：参数指数：key的指数;
    ：类型指数：int
    """

    # 重新生成P和Q值，直到calculate_keys不会引发ValueError    
    while True:
        (p, q) = find_p_q(nbits // 2, getprime_func, accurate)
        try:
            (e, d) = calculate_keys_custom_exponent(p, q, exponent=exponent)
            break
        except ValueError:
            pass

    print(p, "\n", q, "\n", e, "\n", d)
    return p, q, e, d


def newkeys(nbits):
    """生成公钥和私钥，返回(pub, priv)。
    公共密钥也是“加密密钥”，并且是一个
    python类,即`rsa.PublicKey`对象。私钥也被称为“解密密钥”,
    是一个python类,即`rsa.PrivateKey`对象。
    :参数NBITS：存储``N = P * q``所需的比特数。
    :类型指数：INT
    :返回：一个元组（：PY：类：`rsa.PublicKey`，：PY：类：`rsa.PrivateKey`）

    """
    accurate=True; poolsize=1; exponent=DEFAULT_EXPONENT

    if nbits < 16:
        raise ValueError('Key too small')

    if poolsize < 1:
        raise ValueError('Pool size (%i) should be >= 1' % poolsize)

    getprime_func = rsa.prime.getprime

    #  生成key components
    (p, q, e, d) = gen_keys(nbits, getprime_func, accurate=accurate, exponent=exponent)

    # 生成key objects
    n = p * q

    return (
        PublicKey(n, e),
        PrivateKey(n, e, d, p, q)
    )



class AbstractKey(object):
    """公钥和私钥类的共同抽象父类"""

    __slots__ = ('n', 'e')

    def __init__(self, n, e):
        self.n = n
        self.e = e

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):
        """在加载PKCS＃1 PEM格式的密钥，在子类中实现。
        ：参数密钥文件：一个包含PEM编码文件的内容
            公钥。
        ：密钥文件类型：bytes
        ：返回：加载的key
        ：舍入类型：AbstractKey
        """

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        """在加载PKCS＃1 PEM格式的密钥，实现一个子类。
        ：参数密钥文件：包含DER编码文件的内容
            公钥。
        ：密钥文件类型：字节
        ：返回：加载的关键
        ：舍入类型：AbstractKey        
        """

    def _save_pkcs1_pem(self):
        """保存在PKCS＃1 PEM格式的密钥，实现一个子类。
        ：返回：PEM编码的关键。
        ：舍入类型：字节
        """

    def _save_pkcs1_der(self):
        """保存在PKCS＃1 DER格式的关键，实现一个子类。
        ：返回：DER编码的关键。
        ：舍入类型：字节
        """

    @classmethod
    def load_pkcs1(cls, keyfile, format='PEM'):
        """在加载PKCS＃1 DER或PEM格式的密钥。
        ：参数密钥文件：一个DER-或PEM编码文件的内容包含
             钥匙。
        ：密钥文件类型：bytes
        ：参数格式：该文件的格式来加载; “质子交换膜”或“DER”
        ：类型格式：STR
        ：返回：加载的关键
        ：舍入类型：AbstractKey
        """

        methods = {
            'PEM': cls._load_pkcs1_pem,
            'DER': cls._load_pkcs1_der,
        }

        method = cls._assert_format_exists(format, methods)
        return method(keyfile)

    @staticmethod
    def _assert_format_exists(file_format, methods):
        """检查是否存在“方法给出的文件格式.
        """

        try:
            return methods[file_format]
        except KeyError:
            formats = ', '.join(sorted(methods.keys()))
            raise ValueError('Unsupported format: %r, try one of %s' % (file_format,
                                                                        formats))

    def save_pkcs1(self, format='PEM'):
        """保存在PKCS＃1 DER或PEM格式的密钥。
        ：参数格式：格式保存; “质子交换膜”或“DER”
        ：类型格式：STR
        ：返回：DER-或PEM编码的关键。
        ：舍入类型：字节
        """

        methods = {
            'PEM': self._save_pkcs1_pem,
            'DER': self._save_pkcs1_der,
        }

        method = self._assert_format_exists(format, methods)
        return method()

    def blind(self, message, r):
        """执行致盲使用随机数“R”的消息。
        ：参数：消息，为整数，盲目。
        ：消息类型：INT
        ：参数R：随机数盲用。
        ：R型：INT
        ：返回：盲消息。
        ：舍入类型：INT
        blinding 是 message = unblind(decrypt(blind(encrypt(message)))
        见https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """

        return (message * pow(r, self.e, self.n)) % self.n

    def unblind(self, blinded, r):
        """Performs blinding on the message using random number 'r'.

        :param blinded: the blinded message, as integer, to unblind.
        :param r: the random number to unblind with.
        :return: the original message.

        The blinding is such that message = unblind(decrypt(blind(encrypt(message))).

        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29
        """

        return (rsa.common.inverse(r, self.n) * blinded) % self.n


class PublicKey(AbstractKey):
    """Represents a public RSA key.

    This key is also known as the 'encryption key'. It contains the 'n' and 'e'
    values.

    Supports attributes as well as dictionary-like access. Attribute accesss is
    faster, though.

    >>> PublicKey(5, 3)
    PublicKey(5, 3)

    >>> key = PublicKey(5, 3)
    >>> key.n
    5
    >>> key['n']
    5
    >>> key.e
    3
    >>> key['e']
    3

    """

    __slots__ = ('n', 'e')

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'PublicKey(%i, %i)' % (self.n, self.e)

    def __getstate__(self):
        """Returns the key as tuple for pickling."""
        return self.n, self.e

    def __setstate__(self, state):
        """Sets the key from tuple."""
        self.n, self.e = state

    def __eq__(self, other):
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.n, self.e))

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the public
            key.
        :return: a PublicKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MAwCBQCNGmYtAgMBAAE='
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PublicKey._load_pkcs1_der(der)
        PublicKey(2367317549, 65537)

        """

        from pyasn1.codec.der import decoder
        from rsa.asn1 import AsnPubKey

        (priv, _) = decoder.decode(keyfile, asn1Spec=AsnPubKey())
        return cls(n=int(priv['modulus']), e=int(priv['publicExponent']))

    def _save_pkcs1_der(self):
        """Saves the public key in PKCS#1 DER format.

        :returns: the DER-encoded public key.
        :rtype: bytes
        """

        from pyasn1.codec.der import encoder
        from rsa.asn1 import AsnPubKey

        # Create the ASN object
        asn_key = AsnPubKey()
        asn_key.setComponentByName('modulus', self.n)
        asn_key.setComponentByName('publicExponent', self.e)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):
        """Loads a PKCS#1 PEM-encoded public key file.

        The contents of the file before the "-----BEGIN RSA PUBLIC KEY-----" and
        after the "-----END RSA PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key.
        :return: a PublicKey object
        """

        der = rsa.pem.load_pem(keyfile, 'RSA PUBLIC KEY')
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self):
        """Saves a PKCS#1 PEM-encoded public key file.

        :return: contents of a PEM-encoded file that contains the public key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, 'RSA PUBLIC KEY')

    @classmethod
    def load_pkcs1_openssl_pem(cls, keyfile):
        """Loads a PKCS#1.5 PEM-encoded public key file from OpenSSL.

        These files can be recognised in that they start with BEGIN PUBLIC KEY
        rather than BEGIN RSA PUBLIC KEY.

        The contents of the file before the "-----BEGIN PUBLIC KEY-----" and
        after the "-----END PUBLIC KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the public
            key, from OpenSSL.
        :type keyfile: bytes
        :return: a PublicKey object
        """

        der = rsa.pem.load_pem(keyfile, 'PUBLIC KEY')
        return cls.load_pkcs1_openssl_der(der)

    @classmethod
    def load_pkcs1_openssl_der(cls, keyfile):
        """Loads a PKCS#1 DER-encoded public key file from OpenSSL.

        :param keyfile: contents of a DER-encoded file that contains the public
            key, from OpenSSL.
        :return: a PublicKey object
        :rtype: bytes

        """

        from rsa.asn1 import OpenSSLPubKey
        from pyasn1.codec.der import decoder
        from pyasn1.type import univ

        (keyinfo, _) = decoder.decode(keyfile, asn1Spec=OpenSSLPubKey())

        if keyinfo['header']['oid'] != univ.ObjectIdentifier('1.2.840.113549.1.1.1'):
            raise TypeError("This is not a DER-encoded OpenSSL-compatible public key")

        return cls._load_pkcs1_der(keyinfo['key'][1:])


class PrivateKey(AbstractKey):
    """Represents a private RSA key.

    This key is also known as the 'decryption key'. It contains the 'n', 'e',
    'd', 'p', 'q' and other values.

    Supports attributes as well as dictionary-like access. Attribute accesss is
    faster, though.

    >>> PrivateKey(3247, 65537, 833, 191, 17)
    PrivateKey(3247, 65537, 833, 191, 17)

    exp1, exp2 and coef can be given, but if None or omitted they will be calculated:

    >>> pk = PrivateKey(3727264081, 65537, 3349121513, 65063, 57287, exp2=4)
    >>> pk.exp1
    55063
    >>> pk.exp2  # this is of course not a correct value, but it is the one we passed.
    4
    >>> pk.coef
    50797

    If you give exp1, exp2 or coef, they will be used as-is:

    >>> pk = PrivateKey(1, 2, 3, 4, 5, 6, 7, 8)
    >>> pk.exp1
    6
    >>> pk.exp2
    7
    >>> pk.coef
    8

    """

    __slots__ = ('n', 'e', 'd', 'p', 'q', 'exp1', 'exp2', 'coef')

    def __init__(self, n, e, d, p, q, exp1=None, exp2=None, coef=None):
        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q

        # Calculate the other values if they aren't supplied
        if exp1 is None:
            self.exp1 = int(d % (p - 1))
        else:
            self.exp1 = exp1

        if exp2 is None:
            self.exp2 = int(d % (q - 1))
        else:
            self.exp2 = exp2

        if coef is None:
            self.coef = rsa.common.inverse(q, p)
        else:
            self.coef = coef

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return 'PrivateKey(%(n)i, %(e)i, %(d)i, %(p)i, %(q)i)' % self

    def __getstate__(self):
        """Returns the key as tuple for pickling."""
        return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    def __setstate__(self, state):
        """Sets the key from tuple."""
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state

    def __eq__(self, other):
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return (self.n == other.n and
                self.e == other.e and
                self.d == other.d and
                self.p == other.p and
                self.q == other.q and
                self.exp1 == other.exp1 and
                self.exp2 == other.exp2 and
                self.coef == other.coef)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, encrypted):
        """Decrypts the message using blinding to prevent side-channel attacks.

        :param encrypted: the encrypted message
        :type encrypted: int

        :returns: the decrypted message
        :rtype: int
        """

        blind_r = rsa.randnum.randint(self.n - 1)
        blinded = self.blind(encrypted, blind_r)  # blind before decrypting
        decrypted = rsa.core.decrypt_int(blinded, self.d, self.n)

        return self.unblind(decrypted, blind_r)

    def blinded_encrypt(self, message):
        """Encrypts the message using blinding to prevent side-channel attacks.

        :param message: the message to encrypt
        :type message: int

        :returns: the encrypted message
        :rtype: int
        """

        blind_r = rsa.randnum.randint(self.n - 1)
        blinded = self.blind(message, blind_r)  # blind before encrypting
        encrypted = rsa.core.encrypt_int(blinded, self.d, self.n)
        return self.unblind(encrypted, blind_r)

    @classmethod
    def _load_pkcs1_der(cls, keyfile):
        """Loads a key in PKCS#1 DER format.

        :param keyfile: contents of a DER-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object

        First let's construct a DER encoded key:

        >>> import base64
        >>> b64der = 'MC4CAQACBQDeKYlRAgMBAAECBQDHn4npAgMA/icCAwDfxwIDANcXAgInbwIDAMZt'
        >>> der = base64.standard_b64decode(b64der)

        This loads the file:

        >>> PrivateKey._load_pkcs1_der(der)
        PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

        """

        from pyasn1.codec.der import decoder
        (priv, _) = decoder.decode(keyfile)

        # ASN.1 contents of DER encoded private key:
        #
        # RSAPrivateKey ::= SEQUENCE {
        #     version           Version,
        #     modulus           INTEGER,  -- n
        #     publicExponent    INTEGER,  -- e
        #     privateExponent   INTEGER,  -- d
        #     prime1            INTEGER,  -- p
        #     prime2            INTEGER,  -- q
        #     exponent1         INTEGER,  -- d mod (p-1)
        #     exponent2         INTEGER,  -- d mod (q-1)
        #     coefficient       INTEGER,  -- (inverse of q) mod p
        #     otherPrimeInfos   OtherPrimeInfos OPTIONAL
        # }

        if priv[0] != 0:
            raise ValueError('Unable to read this file, version %s != 0' % priv[0])

        as_ints = tuple(int(x) for x in priv[1:9])
        return cls(*as_ints)

    def _save_pkcs1_der(self):
        """Saves the private key in PKCS#1 DER format.

        :returns: the DER-encoded private key.
        :rtype: bytes
        """

        from pyasn1.type import univ, namedtype
        from pyasn1.codec.der import encoder

        class AsnPrivKey(univ.Sequence):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.NamedType('modulus', univ.Integer()),
                namedtype.NamedType('publicExponent', univ.Integer()),
                namedtype.NamedType('privateExponent', univ.Integer()),
                namedtype.NamedType('prime1', univ.Integer()),
                namedtype.NamedType('prime2', univ.Integer()),
                namedtype.NamedType('exponent1', univ.Integer()),
                namedtype.NamedType('exponent2', univ.Integer()),
                namedtype.NamedType('coefficient', univ.Integer()),
            )

        # Create the ASN object
        asn_key = AsnPrivKey()
        asn_key.setComponentByName('version', 0)
        asn_key.setComponentByName('modulus', self.n)
        asn_key.setComponentByName('publicExponent', self.e)
        asn_key.setComponentByName('privateExponent', self.d)
        asn_key.setComponentByName('prime1', self.p)
        asn_key.setComponentByName('prime2', self.q)
        asn_key.setComponentByName('exponent1', self.exp1)
        asn_key.setComponentByName('exponent2', self.exp2)
        asn_key.setComponentByName('coefficient', self.coef)

        return encoder.encode(asn_key)

    @classmethod
    def _load_pkcs1_pem(cls, keyfile):
        """Loads a PKCS#1 PEM-encoded private key file.

        The contents of the file before the "-----BEGIN RSA PRIVATE KEY-----" and
        after the "-----END RSA PRIVATE KEY-----" lines is ignored.

        :param keyfile: contents of a PEM-encoded file that contains the private
            key.
        :type keyfile: bytes
        :return: a PrivateKey object
        """

        der = rsa.pem.load_pem(keyfile, b('RSA PRIVATE KEY'))
        return cls._load_pkcs1_der(der)

    def _save_pkcs1_pem(self):
        """Saves a PKCS#1 PEM-encoded private key file.

        :return: contents of a PEM-encoded file that contains the private key.
        :rtype: bytes
        """

        der = self._save_pkcs1_der()
        return rsa.pem.save_pem(der, b('RSA PRIVATE KEY'))

if __name__ == '__main__':
    import doctest

    try:
        for count in range(100):
            (failures, tests) = doctest.testmod()
            if failures:
                break

            if (count and count % 10 == 0) or count == 1:
                print('%i times' % count)
    except KeyboardInterrupt:
        print('Aborted')
    else:
        print('Doctests done')

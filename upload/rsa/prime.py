# -*- coding: utf-8 -*-

"""与素数相关的数值函数
"""

from rsa._compat import range
import rsa.common
import rsa.randnum

__all__ = ['getprime', 'are_relatively_prime']


def gcd(p, q):
    """返回最大公约数,辗转相除法

    >>> gcd(48, 180)
    12
    """

    while q != 0:
        (p, q) = (q, p % q)
    return p


def get_primality_testing_rounds(number):
    """返回几轮米勒Rabing素性测试的最低数量，
    基于数字bitsize。
    据NIST FIPS186-4，附录C，表C.3的最小数量
    轮M-R的测试，使用的2 **（-100）的误差概率，对
    不同P，Q bitsizes是：
      * P，Q bitsize：512;回合：7
      * P，Q bitsize：1024;回合：4
      * P，Q bitsize：1536;回合：3
    请参阅：http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    """

    # Calculate number bitsize.
    bitsize = rsa.common.bit_size(number)
    # Set number of rounds.
    if bitsize >= 1536:
        return 3
    if bitsize >= 1024:
        return 4
    if bitsize >= 512:
        return 7
    # For smaller bitsizes, set arbitrary number of rounds.
    return 10


def miller_rabin_primality_testing(n, k):
    """计算n是复合（这是总是正确的）或总理
    （理论上是不正确与错误概率4** - K），由
    运用米勒 - 拉宾素性测试。
    借鉴和实现的例子，请参阅：
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    ：参数n为整数，为素性测试。
    ：N型：INT
    ：参数K：发米勒罗宾测试（证人）的数量。
    ：K型：INT
    ：返回：如果假数为复合材料，真要是它可能是素数。
    ：舍入类型：BOOL
    """

    # prevent potential infinite loop when d = 0
    if n < 2:
        return False

    # Decompose (n - 1) to write it as (2 ** r) * d
    # While d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    # Test k witnesses.
    for _ in range(k):
        # Generate random integer a, where 2 <= a <= (n - 2)
        a = rsa.randnum.randint(n - 3) + 1

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # Exit inner loop and continue with next witness.
                break
        else:
            # If loop doesn't break, n is composite.
            return False

    return True


def is_prime(number):
    """如果是素数返回True.

    >>> is_prime(2)
    True
    >>> is_prime(42)
    False
    >>> is_prime(41)
    True
    """

    # 小数的检查.
    if number < 10:
        return number in {2, 3, 5, 7}

    # 偶数.
    if not (number & 1):
        return False

    # 计算最少的回合数.
    k = get_primality_testing_rounds(number)

    # 进行（minimum + 1）轮素性测试。.
    return miller_rabin_primality_testing(number, k + 1)


def getprime(nbits):
    """返回有nbits位的素数.

    >>> p = getprime(128)
    >>> is_prime(p-1)
    False
    >>> is_prime(p)
    True
    >>> is_prime(p+1)
    False

    >>> from rsa import common
    >>> common.bit_size(p) == 128
    True
    """

    assert nbits > 3  # the loop wil hang on too small numbers

    while True:
        integer = rsa.randnum.read_random_odd_int(nbits)

        # Test for primeness
        if is_prime(integer):
            return integer

            # Retry if not prime


def are_relatively_prime(a, b):
    """如果互质就返回True

    >>> are_relatively_prime(2, 3)
    True
    >>> are_relatively_prime(2, 4)
    False
    """

    d = gcd(a, b)
    return d == 1


if __name__ == '__main__':
    print('Running doctests 1000x or until failure')
    import doctest

    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count and count % 100 == 0:
            print('%i times' % count)

    print('Doctests done')

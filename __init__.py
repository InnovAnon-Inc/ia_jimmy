#! /usr/bin/env python3

from functools import partial, reduce
from math import gcd, lcm
from operator import __mul__
from os.path import isfile
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Type, Union

from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization, hashes
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey, DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers
from dataclasses import dataclass
from flask import Blueprint, Flask, jsonify, request
from joblib import dump, load
from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import X509, PKey
from overrides import overrides
from structlog import get_logger
from typeguard import typechecked
from werkzeug.datastructures import FileStorage

from os.path import abspath, dirname
from sys import path

#@typechecked
#def append_file(file:str)->None:
#    abs_path   :str = abspath(file)
#    current_dir:str = dirname(abs_path)              # Get the current script's directory
#    parent_dir :str = dirname(current_dir)           # Get the parent directory by going one level up
#    path.append(parent_dir)                          # Add the parent directory to sys.path
#append_file(__file__)

#from primes.euclid import mod_inv
from ia_gcd import mod_inv

logger            = get_logger()
P_name  :str      = 'psieve.joblib'                  # restartable
P       :int      = 1                                # identity
if isfile(P_name):                                   # load if possible
    P             = load(P_name)

ECPublicKey       = rust_openssl.ec.ECPublicKey
ECPrivateKey      = rust_openssl.ec.ECPrivateKey

CKey              = Union[
        DSAPrivateKey, DSAPublicKey,
        ECPublicKey,   ECPrivateKey,
        RSAPrivateKey, RSAPublicKey,
]

RSAPrivateNumbers = rust_openssl.rsa.RSAPrivateNumbers
RSAPublicNumbers  = rust_openssl.rsa.RSAPublicNumbers

DSAPrivateNumbers = rust_openssl.dsa.DSAPrivateNumbers
DSAPublicNumbers  = rust_openssl.dsa.DSAPublicNumbers

PublicNumbers     = Union[
        DSAPublicNumbers,
        EllipticCurvePublicNumbers,
        RSAPublicNumbers,
]

@typechecked
@dataclass
class RSACrackedKey(RSAPrivateKey):

    pub :RSAPublicKey
    priv:RSAPrivateNumbers

    @overrides
    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    @property
    @overrides
    def key_size(self) -> int:
        return self.pub.key_size()

    @overrides
    def public_key(self) -> RSAPublicKey:
        return self.pub

    @overrides
    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: asym_utils.Prehashed | hashes.HashAlgorithm,
    ) -> bytes:
        raise NotImplementedError()

    @overrides
    def private_numbers(self) -> RSAPrivateNumbers:
        return self.priv

    @overrides
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()

@typechecked
@dataclass
class JimmyCrackerException(Exception):
    """ Jimmy Cracked Key Base Exception"""

@typechecked
@dataclass
class InsufficientAlgorithmException(JimmyCrackerException):
    """ Hacking demands it """

    algorithm:Type

@typechecked
@dataclass
class InsufficientCowbellError(JimmyCrackerException):
    """ Walkens demands it """

    n:int
    P:int

@typechecked
def unpack_pubkey(text:str)->Tuple[int,int]:         # extract normal ints for the equations
    logger.debug('unpack_pubkey(%s)', text)
    cert:X509              = load_certificate(FILETYPE_PEM, text)
    k0  :PKey              = cert.get_pubkey()
    k1  :CKey              = k0.to_cryptography_key()
    k2  :PublicNumbers     = k1.public_numbers()
    if not isinstance(k2, RSAPublicNumbers):
        raise InsufficientAlgorithmException(type(k2))
    #if pubKey.type() == crypto.TYPE_RSA: keyType = 'RSA'
    #elif pubKey.type() == crypto.TYPE_DSA: keyType = 'DSA'
    n   :int               = k2.n
    e   :int               = k2.e
    logger.info('n: %s', n)
    logger.info('e: %s', e)
    return n, e

@typechecked
def unpack_pubkey_o(text:str)->Optional[Tuple[int,int]]: # for the dict comprehension
    try:   
        return unpack_pubkey(text)
    except InsufficientAlgorithmException as e:
        logger.error(e)
    return None

@typechecked
def pack_privkey(n:int, e:int, q:int)->PKey:         # put the ints back into the key
    logger.debug('pack_privkey(%s, %s, %s)', n, e, q)
    assert n % q == 0
    assert q < n, f'n={n}, q={q}'
    p   :int                         = (n // q)
    assert p, f'n={n}, q={q}'
    d   :int                         = private_exponent(n, e, q)
    logger.info('d: %s', d)
    dmp1:int                         = d % (p - 1)   # this probably isn't necessary, but I don't wanna poke the OpenSSL lib
    dmq1:int                         = d % (q - 1)   #
    iqmp:int                         = mod_inv(q, p) #
    k2  :RSAPrivateNumbers           = RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp)
    k1  :CKey                        = RSACrackedKey(k1, k2)
    return                             PKey.from_cryptography_key(k1)
    #cert:X509              = X509.from_cryptography()
    #text:str               = dump_certificate(FILETYPE_PEM, cert)

@typechecked
def private_exponent(n:int, e:int, q:int)->int:      # n = p*q, ln = lcm(p-1, q-1), ed = 1 (mod ln)
    logger.debug('private_exponent(%s, %s, %s)', n, e, q)
    assert n % q == 0
    assert q < n, f'n={n}, q={q}'
    p   :int                         = (n // q)
    assert p-1, f'n={n}, q={q}'
    assert q-1
    ln  :int                         = lcm(p-1, q-1)
    assert ln, f'p={p}, q={q}'
    d   :int                         = mod_inv(e, ln)
    assert (d * e) % ln == 1
    return d

@typechecked                                         # not used
def check_1(n:int)->int:                             # != 1 ==> compromise
    global P
    logger.debug('check_1(%s)', n)
    q   :int                         = gcd(n, P) #if n != P else 1
    P                               *= (n // q)
    dump(P, P_name)
    if q != 1: logger.warning('compromise %s | %s', q, n)
    return q

@typechecked                                         # not used
def public_to_private(pub:str)->PKey:                # RSA inversion oracle
    #logger.debug('public_to_private(%s)', pub)
    n   :int
    e   :int
    n, e                             = unpack_pubkey(pub)
    q   :int                         = check_1(n)
    if q == 1: raise InsufficientCowbellError(n, P)
    if q == n: raise InsufficientCowbellError(n, P) # TODO testing
    return pack_privkey(n, e, q)

@typechecked
def gcd_R(n:int, R:int)->int:                        # Arjen K. Lenstra, James P. Hughes, Maxime Augier, Joppe W. Bos, Thorsten Kleinjung and Christophe Wachter:
    logger.debug('gcd_R(%s, %s)', n, R)
    assert R % n == 0
    return gcd(n, R // n)                            # != 1 ==> compromise

@typechecked
def check_self(N:Iterable[int])->Dict[int,int]:      # Daniel J. Bernstein & Nadia Heninger:
    N  :Set[int]                     = set(N)        # compute the GCD of each RSA key n against the product of all the other keys n'
    logger.debug('check_self(%s)', N)
    R  :int                          = reduce(__mul__, N, 1)
    g  :Callable[[int],int]          = partial(gcd_R, R=R)
    return { n: g(n) for n in N }

@typechecked
def check_helper(n:int, g:int)->int:                 # my sieving algorithm
    global P
    logger.debug('check_helper(%s, %s)', n, g)
    assert n % g == 0
    p  :int                          = (n // g)      # extract (presumably)PF from key
    if p != 1: logger.warning('factor: %s | %s', p, n)
    G  :int                          = gcd(p, P)     # check for matches in sieve / verify that factor is prime
    assert p % G == 0
    r  :int                          = (p // G)      # definitely prime
    if r != 1: logger.warning('prime: %s | %s', r, n)
    P                               *= r             # record prime
    assert n % r == 0
    return                             r             # the best prime factor we've got != 1 ==> compromise

@typechecked
def check_bulk(N:Iterable[int])->Dict[int,int]: 
    #logger.debug('check_bulk(%s)', N) # cast to tuple first
    Q  :Dict[int,int]                = check_self(N) # remove duplicate factors
    R  :Dict[int,int]                = { n: check_helper(n, g) for n, g in Q.items() }
    dump(P, P_name)                                  # save our progress for when we restart
    return R

@typechecked
def process(texts:Iterable[str])->Dict[str,PKey]:    # lookup tables ==> remember original input after so many xforms
    texts                            = set(texts)
    logger.debug('process(%s)', len(texts))
    tne:Dict[str,Optional[Tuple[int,int]]] = { t: unpack_pubkey_o(t) for t in texts }
    TNE:Dict[str,Tuple[int,int]]     = { t: ne for t, ne in tne.items() if ne }
    N  :Iterable[int]                = { n for n, e in TNE.values() }
    NQ :Dict[int,int]                = check_bulk(N)
    TNQ:Dict[str,Tuple[int,int,int]] = { t: (n, e, NQ[n]) for t, (n, e) in TNE.items() }
    return { t: pack_privkey(*TNQ[t]) for t in texts }

#@typechecked
#def create_app(name:str)->Flask:                     # process() as a service
#    logger.debug('create_app(%s)', name)
#    app:Flask                        = Flask(name)
#
#    @app.route('/psieve/', methods=['POST'])
#    def psieve()->str:
#        assert request.method == 'POST'
#        #logger.debug('psieve(%s)', len(request.files.values()))
#        F:Iterable[FileStorage]       = request.files.values()
#        r:Callable[[FileStorage],str] = lambda f: f.read()
#        i:Iterable[str]               = map(r, F)
#        o:Dict[str,PKey]              = process(i)
#        return jsonify(o)
#
#    return app
#
#@typechecked
#def run_app(name:str)->None:
#    app:Flask                        = create_app(name)
#    app.run(host='0.0.0.0', port='9100')
#
#if __name__ == '__main__':
#    run_app(__name__)

__author__    :str = "AI Assistant"
__copyright__ :str = "Copyright 2024, InnovAnon, Inc."
__license__   :str = "Proprietary"
__version__   :str = "1.0"
__maintainer__:str = "@lmaddox"
__email__     :str = "InnovAnon-Inc@gmx.com"
__status__    :str = "Development"

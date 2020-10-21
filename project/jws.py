import base64
import json
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives import serialization
from collections import OrderedDict
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding


def bytes_from_int(val):
    """TODO https://github.com/jpadilla/pyjwt/blob/master/jwt/compat.py
    """
    remaining = val
    byte_length = 0

    while remaining != 0:
        remaining = remaining >> 8
        byte_length += 1

    return val.to_bytes(byte_length, 'big', signed=False)


def base64url_encode(input):
    """ TODO https://github.com/jpadilla/pyjwt/blob/master/jwt/utils.py
    """
    return base64.urlsafe_b64encode(input).replace(b'=', b'')


def to_base64url_uint(val):
    """ TODO https://github.com/jpadilla/pyjwt/blob/master/jwt/utils.py

    """
    if val < 0:
        raise ValueError('Must be a positive integer')

    int_bytes = bytes_from_int(val)

    if len(int_bytes) == 0:
        int_bytes = b'\x00'

    return base64url_encode(int_bytes)


def decode(data: bytes) -> dict:
    """
    >>> decode(b'eyJhbGciOiJSUzI1NiJ9')
    {'alg': 'RS256'}

    :param data:
    :return:
    """
    return json.loads(base64.urlsafe_b64decode(data).decode("utf"))


def encode(obj: dict) -> bytes:
    """
    >>> encode({"alg": "RS256"})
    b'eyJhbGciOiJSUzI1NiJ9'

    :param obj: a dict
    :return: base64 representation
    """
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(',', ':')).encode('utf-8')).replace(b"=", b"")


class JWS:
    """ Implements a subset of JWS as specified in RFC 7517

    For our case we have the following additional constraints:
        * The JWS Protected Header must include:
            * alg - neither containing none nor a MAC
            * nonce
            * url
            * jwk (new Account and revokeCert) or kid
        * Because client requests in ACME carry JWS objects in the Flattened
        JSON Serialization, they must have the Content-Type header field set
        to "application/jose+json".
        * If we do not have a payload, we send the empty string as payload.

    The current implementation takes a header, payload and a privatekey and crafts a Flattened JWS object with
    signature.
    """
    def __init__(self, key: RSAPrivateKey):
        self.key = key

    def generate(self, header, payload):

        data = {
            "protected": encode(header).decode("utf-8"),
            "payload": encode(payload).decode("utf-8"),
            "signature": self.sign(header, payload, self.key).decode("utf-8")
        }

        return data

    def generate_post_as_get(self, header):
        data = {
            "protected": encode(header).decode("utf-8"),
            "payload": "",
            "signature": base64url_encode(self.key.sign(encode(header)+b'.', padding.PKCS1v15(), hashes.SHA256())).decode('utf-8')
        }
        
        return data

    @staticmethod
    def sign(header, payload, key) -> bytes:
        sign_this = encode(header) + b"." + encode(payload)
        return base64url_encode(
            key.sign(sign_this, padding.PKCS1v15(), hashes.SHA256())
        )

    @property
    def jwk(self):
        return self._to_jwk(self.key.public_key())

    @staticmethod
    def _to_jwk(key: RSAPublicKey) -> dict:
        """ Gives the jwk representation 1given a RSAPublicKey (from the cryptography library)
        see https://tools.ietf.org/html/rfc7517 for details

        :param key: An RSAPublicKey from the cryptography library
        :return: a dict representing the key in JWK format
        """
        # Public key
        numbers = key.public_numbers()

        obj = {
            'alg': 'RS256',
            'kty': 'RSA',
            'n': to_base64url_uint(numbers.n).decode('utf-8'),
            'e': to_base64url_uint(numbers.e).decode('utf-8'),
            'kid': '1'  # TODO do I have to change this?
        }
        return obj

    def csr(self, subject_names):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_names[0]),
        ]))

        # add all subjects

        x509_names = [x509.DNSName(subject) for subject in subject_names]
        builder = builder.add_extension(x509.SubjectAlternativeName(x509_names), critical=False)

        request = builder.sign(self.key, hashes.SHA256(), default_backend())
        return base64url_encode(request.public_bytes(Encoding.DER)).decode("utf-8")

    def jwk_thumbprint(self):
        """ From https://tools.ietf.org/html/rfc7638#section-3

        The thumbprint of a JSON Web Key (JWK) is computed as follows:

       1.  Construct a JSON object [RFC7159] containing only the required
           members of a JWK representing the key and with no whitespace or
           line breaks before or after any syntactic elements and with the
           required members ordered lexicographically by the Unicode
           [UNICODE] code points of the member names.  (This JSON object is
           itself a legal JWK representation of the key.)

       2.  Hash the octets of the UTF-8 representation of this JSON object
           with a cryptographic hash function H.  For example, SHA-256 [SHS]
           might be used as H.

       3.  base64 encode it.
        """
        start_jwk = self.jwk

        new_jwk = OrderedDict()

        # lexically order it
        new_jwk['e'] = start_jwk['e']
        new_jwk['kty'] = start_jwk['kty']
        new_jwk['n'] = start_jwk['n']

        # turn to bytes
        hash_this = json.dumps(new_jwk, separators=(",", ":")).encode('utf-8')

        # hash it
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(hash_this)
        hashed = digest.finalize()

        return base64url_encode(hashed).decode('utf-8')

    def dns_challenge_thumbprint(self, token):
        """ compute base64( hash( token || . || jwk_thumbprint ) )

        :param token: token of a acme-dns challenge
        :return:
        """
        base = token + '.' + self.jwk_thumbprint()

        # hash it
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(base.encode('utf-8'))
        hashed = digest.finalize()

        return base64url_encode(hashed).decode('utf-8')

    def save_private_key(self, path):
        """Saves the private key in the pem PKCS8 format, unencrypted"""

        private_bytes = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        with open(path, 'w') as fo:
            fo.write(private_bytes.decode())


if __name__ == '__main__':

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    handler = JWS(key)
    print(handler.jwk_thumbprint())
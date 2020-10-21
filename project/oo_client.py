"""
Implementation of an ACME client - see https://tools.ietf.org/html/rfc8555
From the rfc:

Protocol Overview
=================

The first phase of ACME is for the client to request an account with
the ACME server.  The client generates an asymmetric key pair and
requests a new account. The creation request is
signed with the generated private key to prove that the client
controls it.

Once an account is registered, there are four major steps the client
needs to take to get a certificate:
1.  Submit an order for a certificate to be issued
2.  Prove control of any identifiers requested in the certificate
3.  Finalize the order by submitting a CSR
4.  Await issuance and download the issued certificate

+-------------------+--------------------------------+--------------+
| Action            | Request                        | Response     |
+-------------------+--------------------------------+--------------+
| Get directory     | GET  directory                 | 200          |
| Get nonce         | HEAD newNonce                  | 200          |
| Create account    | POST newAccount                | 201 ->       |
|                   |                                | account      |
| Submit order      | POST newOrder                  | 201 -> order |
| Fetch challenges  | POST-as-GET order's            | 200          |
|                   | authorization urls             |              |
| Respond to        | POST authorization challenge   | 200          |
| challenges        | urls                           |              |
| Poll for status   | POST-as-GET order              | 200          |
| Finalize order    | POST order's finalize url      | 200          |
| Poll for status   | POST-as-GET order              | 200          |
| Download          | POST-as-GET order's            | 200          |
| certificate       | certificate url                |              |
+-------------------+--------------------------------+--------------+

Account creation
~~~~~~~~~~~~~~~~
All ACME requests with a non-empty body MUST encapsulate their
payload in a JSON Web Signature (JWS) [RFC7515] object, signed using
the account's private key unless otherwise specified.

For newAccount requests, and for revokeCert requests authenticated by
a certificate key, there MUST be a "jwk" field.  This field MUST
contain the public key corresponding to the private key used to sign
the JWS.
"""
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import jws

import typing
import requests

import dns
import https_server

class StatusCodes:
    bad_nonce = "urn:ietf:params:acme:error:badNonce"


class Config:
    """ A container for the various endpoints of a letsencrypt-CA

    From rfc8555:
    +------------+--------------------+
    | Field      | URL in Value       |
    +------------+--------------------+
    | newNonce   | New nonce          |
    | newAccount | New account        |
    | newOrder   | New order          |
    | newAuthz   | New authorization  |
    | revokeCert | Revoke certificate |
    | keyChange  | Key change         |
    +------------+--------------------+

    We do not use the newAuthz field, since we do not implement pre-authorization.
    """

    def __init__(self, server_config: dict):
        self.key_change = server_config["keyChange"]
        self.new_account = server_config["newAccount"]
        self.new_nonce = server_config["newNonce"]
        self.new_order = server_config["newOrder"]
        self.revoke_cert = server_config["revokeCert"]


class Challenge:

    def __init__(self, challenge: dict, subject):
        self.type = challenge['type']
        self.url = challenge['url']
        self.status = challenge['status'] if 'status' in challenge else None
        self.token = challenge['token']
        self.subject = subject  # each challenge is for a specific subject

    def __str__(self):
        return f"{self.status} {self.type} challenge at {self.url}"

    def __repr__(self):
        return self.__str__()


class Session:
    def __init__(self, kid: str, nonce: str):
        self.kid = kid
        self.nonce = nonce


class Order:
    """
    Stores the urls of a particular order
    """

    def __init__(self, authorizations, finalize, order_url, domains):
        self.authorizations = authorizations
        self.finalize = finalize
        self.order_url = order_url
        self.domains = domains


class API:

    def __init__(self, acme_dir: str):
        self.config = Config(requests.get(acme_dir, verify='pebble_minica.pem').json())
        self.jws = self.generate_crypto_stuff()
        self.session = self.create_account()

    def send(self, location: str, body: typing.Union[dict, None], use_kid=True, post_as_get=False):
        """Sends a post request to the acme server, handles the jws stuff
        if the server rejects our nonce we retry three times"""

        # if we haven't created an account yet, there is no Session obj with the current nonce -
        # we generate the first nonce ourselves
        if 'session' not in self.__dict__:
            nonce = self.get_nonce()
        else:
            nonce = self.session.nonce

        protected_header = {
            "alg": "RS256",
            "nonce": nonce,
            "url": location
        }
        if use_kid:
            protected_header["kid"] = self.session.kid
        else:
            protected_header["jwk"] = self.jws.jwk

        if post_as_get:
            payload = self.jws.generate_post_as_get(protected_header)
        else:
            payload = self.jws.generate(protected_header, body)

        # retry up to three times
        headers = {'Content-Type': 'application/jose+json'}
        r = requests.post(location, json=payload, headers=headers, verify='pebble_minica.pem')
        print('payload', payload)
        for i in range(5):
            if r.status_code == 400 and r.json()["type"] == StatusCodes.bad_nonce:
                print("got a bad nonce, retrying... {}/5".format(i+1))

                # forge a new request with a new nonce
                protected_header['nonce'] = self.get_nonce()
                if post_as_get:
                    payload = self.jws.generate_post_as_get(protected_header)
                else:
                    payload = self.jws.generate(protected_header, body)

                r = requests.post(location, json=payload, headers=headers, verify='pebble_minica.pem')
            else:
                if 'session' in self.__dict__:  # save the replay nonce if possible
                    self.session.nonce = r.headers['Replay-Nonce']
                return r
        sys.exit(1)  # got a bad nonce three times in a row, something is fundamentally broken

    def get_nonce(self):
        """Implements sect. 7.2 of RFC8555 to get a fresh nonce"""
        return requests.head(self.config.new_nonce, verify='pebble_minica.pem').headers['Replay-Nonce']

    @staticmethod
    def generate_crypto_stuff() -> jws.JWS:
        """ Generates a new RSA keypair and sets up the jws stuff.

        :return: JWS object
        """
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        jws_handler = jws.JWS(key)
        return jws_handler

    def create_account(self) -> Session:
        """ See https://tools.ietf.org/html/rfc8555#section-7.3 for details
        From https://www.rfc-editor.org/rfc/rfc7518.txt on acme algs:
        | RS256        | RSASSA-PKCS1-v1_5 using SHA-256

        takes the initial nonce
        returns a session
        """

        body = {
           "termsOfServiceAgreed": True,
         }
        r = self.send(self.config.new_account, body, use_kid=False)

        if r.status_code == 201:
            print("Created a new account")
            print("KID:", r.headers['Location'])
            return Session(kid=r.headers['Location'], nonce=r.headers['Replay-Nonce'])
        else:
            print(r.text)
            raise RuntimeError("Couldn't create a session")

    def order_certificate(self, domains):
        """ This function aims to implement https://tools.ietf.org/html/rfc8555#section-7.4

        :return: an order obj
        """
        # TODO add parameter subject and store it in the Order obj

        body = {
            "identifiers": [{"type": "dns", "value": domain} for domain in domains]
        }

        r = self.send(self.config.new_order, body)

        print("Response of order certificate:")
        print(r.status_code)
        print(r.json())
        data = r.json()
        return Order(data['authorizations'], data["finalize"], r.headers["Location"], domains)

    def get_challenges(self, order: Order) -> typing.List[Challenge]:
        """

        :param authorizations_url:
        :param session: A Session obj
        :return:
        """
        # todo handle more than one authorization

        challenges = []
        for authorizations_url in order.authorizations:
            print("Attempting to get challenge at {}".format(authorizations_url))

            r = self.send(authorizations_url, None, post_as_get=True)
            self.session.nonce = r.headers['Replay-Nonce']

            print(r.text)

            challenges += [Challenge(element, r.json()["identifier"]["value"]) for element in r.json()['challenges']]
        return challenges

    def dns_challenge(self, challenge: Challenge, dnsserver: dns.Server, order: Order):
        """A client fulfills this challenge by constructing a key authorization
       from the "token" value provided in the challenge and the client's
       account key.  The client then computes the SHA-256 digest [FIPS180-4]
       of the key authorization.

       The record provisioned to the DNS contains the base64url encoding of
       this digest.  The client constructs the validation domain name by
       prepending the label "_acme-challenge" to the domain name being
       validated, then provisions a TXT record with the digest value under

       that name.  For example, if the domain name being validated is
       "www.example.org", then the client would provision the following DNS
       record:

       _acme-challenge.www.example.org. 300 IN TXT "gfj9Xq...Rg85nM"
       """
        # todo broken - fix pls
        print("Attempting dns challenge:")
        print(challenge)

        # we need to provision for www.example.org:
        # _acme-challenge.www.example.org. 300 IN TXT "gfj9Xq...Rg85nM"
        # url, ttl, , type, keyauth=token.base64(thumb(accountkey))

        url = "_acme-challenge.{}.".format(challenge.subject)
        dnsserver.set_txt_record(url, self.jws.dns_challenge_thumbprint(challenge.token))

        r = self.send(location=challenge.url, body={})
        print(r.text)
        print(r.headers)

    def http_challenge(self, challenge: Challenge):
        """
        With HTTP validation, the client in an ACME transaction proves its
       control over a domain name by proving that it can provision HTTP
       resources on a server accessible under that domain name.  The ACME
       server challenges the client to provision a file at a specific path,
       with a specific string as its content.

        As a domain may resolve to multiple IPv4 and IPv6 addresses, the
       server will connect to at least one of the hosts found in the DNS A
       and AAAA records, at its discretion.  Because many web servers
       allocate a default HTTPS virtual host to a particular low-privilege
       tenant user in a subtle and non-intuitive manner, the challenge must
       be completed over HTTP, not HTTPS.

       """
        print("Attempting http challenge:")
        print(challenge)

        # do challenge
        with open("acme-challenges/{}".format(challenge.token), "w") as fo:
            fo.write(challenge.token+"."+self.jws.jwk_thumbprint())
        r = self.send(challenge.url, {})

    def finalize(self, order: Order):
        """Tells the server that we completed the challenges and would now like our cert,
        includes a CSR in the post

        example post:
           POST /acme/order/TOlocE8rfgo/finalize HTTP/1.1
       Host: example.com
       Content-Type: application/jose+json

       {
         "protected": base64url({
           "alg": "ES256",
           "kid": "https://example.com/acme/acct/evOfKhNU60wg",
           "nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
           "url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
         }),
         "payload": base64url({
           "csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
         }),
         "signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
       }
        """
        global key2 
        global jws2 
        key2 = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
        jws2 = jws.JWS(key2)

        print("----------CSR STARTS HERE-------")
        csr = jws2.csr(order.domains)
        print(csr)
        print("----------CSR ENDS HERE-------")

        body = {
            "csr": csr
        }

        r = self.send(order.finalize, body)

        print(r.text)
        self.session.nonce = r.headers['Replay-Nonce']
        return r

    def pag_get_cert(self, order):
        """Used after server has (hopefully) processed the request - only a post as get"""

        # get cert url
        r = self.send(order.order_url, None, post_as_get=True)
        print(r.text)
        print("-------Printed r.text-------")
        # download cert
        print("-------Printing r.json-------")
        print(r.json())

        cert_url = r.json()["certificate"]
        print("downloading cert at {}".format(cert_url))
        r = self.send(cert_url, None, post_as_get=True)
        print('cert')
        print(r.text)
        print('cert end')
        return r.text

    def setup_secure_webserver(self, certs, ip):
        """sets up a secure webserver with the needed certs"""
        certpath, keypath = 'certs', 'key'
        print('here')
        with open(certpath, 'w') as fo:
            fo.write(certs)
        print('FINISHED WRITING certs')    
        jws2.save_private_key(keypath)
        print('FINISHED SAVING PRIVATE KEY')    

        https_server.start_server(certpath, keypath, ip)
        print('FINISHED SETUP WEBSERVER')

    def revoke(self, certs):
        # transform a pem cert into a der cert
        cert = certs.split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----'
        cert = cert.encode()
        print(cert)
        cert = x509.load_pem_x509_certificate(cert, default_backend())

        cert = jws.base64url_encode(cert.public_bytes(Encoding.DER)).decode()
        print(cert)

        body = {
            'certificate': cert
        }
        r = self.send(self.config.revoke_cert, body)

        print('printing response of revocation: ', r.status_code, r.text)
import argparse

import dns
import oo_client
import http_server
from multiprocessing import Process
import functools
import time


def cli():
    parser = argparse.ArgumentParser(description="A minimal acme client")
    parser.add_argument('challenge_type')
    parser.add_argument('--dir', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--domain', required=True, action='append')
    parser.add_argument('--revoke', action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    args = cli()
    print(args)
    print("Args dir : ", args.dir)

    dnsserver = dns.Server(args.record)

    # start webserver and add its process to the killable processes
    webserver_starter = functools.partial(http_server.run, args.record)
    webserver = Process(target=webserver_starter)
    webserver.start()

    acme = oo_client.API(args.dir)
    time.sleep(8)
    order = acme.order_certificate(args.domain)
    time.sleep(8)
    challenges = acme.get_challenges(order)
    time.sleep(8)
    print("--------------------Will start DNS CHALLENGE--------------------")

    for challenge in challenges:
        if args.challenge_type == "http01" and challenge.type == "http-01":
            acme.http_challenge(challenge)
        elif args.challenge_type == "dns01" and challenge.type == "dns-01":
            acme.dns_challenge(challenge, dnsserver, order)
    print("--------------------FINISHED DNS CHALLENGE--------------------")
        

    time.sleep(8)
    print("--------------------START FINALIZE--------------------")

    acme.finalize(order)
    print("--------------------FINISH FINALIZE--------------------")

    time.sleep(8)
    print("--------------------here starts the order url--------------------")

    print(order.order_url)
    print("--------------------here ends the order url--------------------")
    certs = acme.pag_get_cert(order)

    if args.revoke:
        acme.revoke(certs)

    secure_webserver_starter = functools.partial(acme.setup_secure_webserver, certs, args.record)
    swebserver = Process(target=secure_webserver_starter)
    swebserver.start()

# invocation:
# project/run dns01 --dir https://127.0.0.1:14000/dir --record 127.0.0.1 --domain www.example.com
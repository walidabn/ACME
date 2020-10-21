""" Dns server running on UDP 10053

"""

import dnslib
import socketserver
from threading import Thread


class Handler(socketserver.BaseRequestHandler):

    TXT_LOOKUP = {}
    DNS_LOOKUP = ''

    def handle(self):

        request = dnslib.DNSRecord.parse(self.request[0])
        """ see http://www.networksorcery.com/enp/protocol/dns.htm 
        QR flag is 1 (0 = Query, 1 = Response)
        AA flag is 1 (0 = Not authoritative, 1 = Is authoritative)
        
        """
        reply = dnslib.DNSRecord(dnslib.DNSHeader(id=request.header.id, qr=1, aa=1),
                                 q=request.q)

        reply.add_answer(dnslib.RR(
            rname=request.q.qname,
            rtype=1,
            rdata=dnslib.A(self.DNS_LOOKUP),

        ))

        request_name = str(request.q.qname)
        if request_name in self.TXT_LOOKUP:
            for answer in self.TXT_LOOKUP[request_name]:
                reply.add_answer(dnslib.RR(
                    request.q.qname,
                    ttl=300,
                    rtype=dnslib.QTYPE.TXT,
                    rdata=dnslib.TXT(answer.encode("utf-8"))
                ))
                print('dnsserver served txt record for {}: {}'.format(request_name, answer))
        else:
            print('dnsserver didn\'t find txt record for {}'.format(request_name))
            # print("{} not in memory".format(request_name))
            # print("memory", self.TXT_LOOKUP)
            # print(type(request_name))
            pass

        self.send_data(reply.pack())

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


class Server:
    def __init__(self, ip):
        self.server = socketserver.ThreadingUDPServer(('', 10053), Handler)
        Handler.DNS_LOOKUP = ip  # ensures that our dns server always replies with the specified ip
        self.t = Thread(target=self.server.serve_forever, daemon=True)
        self.t.start()

    def set_txt_record(self, url, response):
        print("Adding txt record: {}: {}".format(url, response))
        if url not in Handler.TXT_LOOKUP:
            Handler.TXT_LOOKUP[url] = [response]
        else:
            Handler.TXT_LOOKUP[url].append(response)

    def quit(self):
        # todo implement with stuff to do this -- see https://docs.python.org/3/library/socketserver.html
        print("closing the server")
        self.server.server_close()
        self.t.join()
        print("server closed")


def run(ip):
    Server(ip)

if __name__ == '__main__':
    dnsserver = socketserver.ThreadingUDPServer(('', 10053), Handler)
    dnsserver.serve_forever()


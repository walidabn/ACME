import ssl

from flask import Flask

app = Flask(__name__)


@app.route("/")
def main():
    return "Top-level content"


def start_server(certpath, keypath, ip='127.0.0.1'):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certpath, keypath)
    app.run(ip, port=5001, ssl_context=context)

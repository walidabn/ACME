"""
A very simple http server which serves the files in the acme-challenge folder
Runs on port 5002

"""

from flask import Flask, send_from_directory

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello World!"


@app.route("/.well-known/acme-challenge/<path:challenge>")
def acme(challenge):
    """Serves http://{domain}/.well-known/acme-challenge/{token}

    :param challenge:
    :return:
    """
    return send_from_directory('acme-challenges', challenge)


def run(ip):
    print('starting webserver')
    app.run(ip, port=5002)


if __name__ == "__main__":
    app.run(port=5002)

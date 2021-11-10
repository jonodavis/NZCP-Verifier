import verifier
from flask import Flask, request

api = Flask(__name__)

@api.route('/verify', methods=['POST'])
def verify():
  try:
    req = request.get_json()
    res = verifier.check_code(req["payload"])
    return res
  except:
    return {"validated": False} 

if __name__ == '__main__':
  api.run()
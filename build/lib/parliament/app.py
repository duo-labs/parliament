from flask import Flask, request, jsonify
from . import analyze_policy_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def lint():
    if request.method == 'GET' or len(request.json) == 0:
        return jsonify({"usage": "Send a POST request with the json policy document in the body"})
    content = request.json
    analyzed_policy = analyze_policy_string(content['policy'])
    return jsonify([finding.to_json() for finding in analyzed_policy.findings])

if __name__ == '__main__':
    app.run(host= '0.0.0.0', debug=True)
from flask import Flask, request, jsonify
from parliament import analyze_policy_string, enhance_finding
import json

api = Flask(__name__)

@api.route('/', methods=['GET', 'POST'])
def lint():
    if request.method == 'GET' or len(request.json) == 0:
        return jsonify({"usage": "Send a POST request with the json policy document in the body"})
    content = request.json
    analyzed_policy = analyze_policy_string(json.dumps(content))
    findings = set(analyzed_policy.findings)
    findings = [enhance_finding(finding) for finding in findings]
    return jsonify([finding.to_json() for finding in findings])

if __name__ == '__main__':
    api.run(host= '0.0.0.0', debug=True)

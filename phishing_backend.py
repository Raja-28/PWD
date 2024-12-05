from flask import Flask, request, jsonify
from transformers import pipeline
import re
import requests


app = Flask(__name__)


classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")


def extract_url_features(url):
    features = {}
    features['length'] = len(url)
    features['has_ip'] = int(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', url.split("//")[-1].split("/")[0]) is not None)
    features['has_https'] = int(url.startswith("https://"))
    features['suspicious_keywords'] = len(re.findall(r'login|secure|account|update|verify|confirm', url, re.I))
    return features


def check_domain_reputation(domain):
    api_key = "AIzaSyCaVLZtY7R0wrT0ZGBiwhZaJf2MEfsCpdA"  
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "Phishing Website Detection",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": domain}]
        }
    }

    response = requests.post(url, json=payload)
    return response.json()

def detect_phishing(url):
    candidate_labels = ["phishing", "legitimate"]
    features = extract_url_features(url)
    
   
    model_input = (
        f"URL: {url}, Length: {features['length']}, "
        f"Contains IP: {features['has_ip']}, HTTPS: {features['has_https']}, "
        f"Suspicious Keywords: {features['suspicious_keywords']}"
    )

    result = classifier(model_input, candidate_labels)
    
    prediction = result['labels'][0]  
    score = result['scores'][0] * 100  

  
    if score < 70: 
        prediction = "unknown"

    return prediction, score


@app.route('/detect', methods=['POST'])
def detect():
    
    data = request.json
    if 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400

    url = data['url']
    
   
    prediction, confidence = detect_phishing(url)
    
  
    domain_reputation = check_domain_reputation(url)
    is_malicious = bool(domain_reputation.get("matches"))

  
    return jsonify({
        'url': url,
        'prediction': prediction,
        'confidence': confidence,
        'malicious': is_malicious,
        'domain_reputation': domain_reputation if is_malicious else None
    })


if __name__ == '__main__':
    app.run(debug=True)

import streamlit as st
from transformers import pipeline
import whois  # Python WHOIS library
import tldextract  # For extracting domain parts
import pandas as pd
import ssl
import requests
from datetime import datetime
import re

# Initialize the zero-shot classification pipeline
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

# Function to detect phishing
def detect_phishing(url):
    candidate_labels = ["phishing", "legitimate"]
    result = classifier(url, candidate_labels)
   
    prediction = result['labels'][0]  # Top predicted label
    score = result['scores'][0] * 100  # Confidence score as a percentage
    return prediction, score

# Function to get domain information using whois
def get_domain_info(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"  # Extract domain (e.g., google.com)
       
        if not domain or domain == ".":
            raise ValueError("Invalid domain extracted from URL")
       
        st.info(f"Performing WHOIS lookup for domain: {domain}")
        domain_info = whois.whois(domain)
       
        info = {
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Date": domain_info.creation_date,
            "Expiration Date": domain_info.expiration_date,
            "Status": domain_info.status,
            "Name Servers": domain_info.name_servers
        }
        return info
    except Exception as e:
        st.warning(f"Could not retrieve domain information: {e}")
        return None

# Function to check for SSL certificate
def check_ssl(url):
    try:
        hostname = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        cert = ssl.get_server_certificate((hostname, 443))
        return True  # SSL certificate is valid
    except Exception as e:
        st.warning(f"SSL Certificate error: {e}")
        return False  # SSL certificate is not valid

# Function to validate URL format
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None

# Function to expand URL
def expand_url(url):
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Validate URL format
    if not is_valid_url(url):
        st.warning("Invalid URL format.")
        return None

    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        response.raise_for_status()  # Raises an error for bad responses
        return response.url  # This will return the expanded URL
    except requests.exceptions.RequestException as e:
        st.warning(f"Could not expand URL: {e}")
        return None

# Function to generate a downloadable report
def generate_report(url, result, confidence):
    report_data = {
        "URL": [url],
        "Classification": [result],
        "Confidence Level (%)": [confidence]
    }
    df = pd.DataFrame(report_data)
    return df

# Function to log history
def log_history(url, result, confidence):
    history_data = {
        "Timestamp": [datetime.now()],
        "URL": [url],
        "Result": [result],
        "Confidence": [confidence]
    }
    df = pd.DataFrame(history_data)
    df.to_csv('phishing_history.csv', mode='a', header=False, index=False)

# Function to read history
def read_history():
    try:
        return pd.read_csv('phishing_history.csv', names=["Timestamp", "URL", "Result", "Confidence"], header=None)
    except FileNotFoundError:
        return pd.DataFrame(columns=["Timestamp", "URL", "Result", "Confidence"])  # Return empty DataFrame if file doesn't exist

# Main application logic
def main():

   

    st.markdown("<h1 style='text-align: center;'>🔒 Phishing Website Detection</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Using NLP and machine learning to detect phishing websites.</p>", unsafe_allow_html=True)
    st.image('logo.webp', use_column_width=True)
    url = st.text_input("🔗 Enter the website URL to check:")

    
    if st.button("🚨 Detect Phishing"):
        if url:
            # Expand URL
            expanded_url = expand_url(url)
            if expanded_url:
                st.info(f"Expanded URL: {expanded_url}")
            else:
                st.warning("URL expansion failed. Proceeding with the original URL.")
                expanded_url = url  # Fallback to the original URL

            # Check SSL certificate
            ssl_status = check_ssl(expanded_url)
            st.info(f"SSL Certificate Valid: {'Yes' if ssl_status else 'No'}")

            # Get domain information
            domain_info = get_domain_info(expanded_url)
            if domain_info:
                st.subheader("🔍 Domain Information")
                for key, value in domain_info.items():
                    st.write(f"**{key}:** {value}")
            else:
                st.error("No domain information could be retrieved.")

            # Get results from the detection function
            result, confidence = detect_phishing(expanded_url)

            # Display results with emphasis on phishing classification
            st.subheader(f"🚨 This website is classified as **{result.upper()}**!")
            st.subheader(f"Confidence Level: **{confidence:.2f}%**")

            # Log history
            log_history(expanded_url, result, confidence)

            # Display phishing warnings
            if result == "phishing":
                st.markdown("<div style='background-color:#ffcccc;padding:10px;border-radius:5px;'>⚠️ <b>Warning:</b> This site seems to be a phishing attempt!</div>", unsafe_allow_html=True)

            # Generate and download report
            df = generate_report(expanded_url, result, confidence)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="⬇️ Download Report",
                data=csv,
                file_name='phishing_report.csv',
                mime='text/csv',
            )

    # Recent searches/history section
    st.subheader("🕒 Recent Searches")
    history_df = read_history()
    if not history_df.empty:
        st.dataframe(history_df)

    # Sidebar with app info
    st.sidebar.title("ℹ️ About This App")
    st.sidebar.info("""This Phishing Website Detection app uses **transformers** for zero-shot classification. It identifies websites as either **phishing** or **legitimate** based on the URL input.""")

if __name__ == '__main__':
    main()

import streamlit as st
from transformers import pipeline
import tldextract
import validators
import pandas as pd
import whois as whois_query
import datetime
import requests
import matplotlib.pyplot as plt
import base64


def load_model():
    try:
        return pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        return None


def extract_domain_info(url):
    extracted = tldextract.extract(url)
    protocol = "https" if url.startswith("https") else "http"
    domain = f"{extracted.domain}.{extracted.suffix}"  
    subdomain = extracted.subdomain
    return protocol, domain, subdomain


def detect_phishing(classifier, domain):
    candidate_labels = ["phishing", "legitimate"]
    try:
        result = classifier(domain, candidate_labels)
    except Exception as e:
        st.error(f"Error during classification: {str(e)}")
        return None, None

    prediction = result['labels'][0] 
    score = result['scores'][0] * 100 
    return prediction, score

def get_domain_info(domain):
    try:
        domain_info = whois_query.whois(domain) 
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            domain_age = (datetime.datetime.now() - creation_date).days
        else:
            domain_age = None

        registrar = domain_info.registrar
        country = domain_info.country
        status = domain_info.status

        return {
            "age": domain_age,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "registrar": registrar,
            "country": country,
            "status": status
        }

    except Exception as e:
        st.error(f"Error retrieving domain info: {str(e)}")
        return None


def add_to_history(df, url, domain, result, confidence, domain_age):
    new_entry = pd.DataFrame([[url, domain, result, f"{confidence:.2f}%", domain_age]], 
                             columns=["URL", "Domain", "Result", "Confidence", "Domain Age (days)"])
    df = pd.concat([df, new_entry], ignore_index=True)
    return df


def plot_pie_chart(result, confidence):
    if result == "legitimate":
        sizes = [confidence, 100 - confidence]
        colors = ['green', 'red'] 
    else:
        sizes = [100 - confidence, confidence]
        colors = ['green', 'red']  
    labels = ['Legitimate Confidence', 'Phishing Confidence']
    
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  

    return fig

def main():
    if 'history' not in st.session_state:
        st.session_state.history = pd.DataFrame(columns=["URL", "Domain", "Result", "Confidence", "Domain Age (days)"])

    st.markdown("<h1 style='text-align: center;'>🔒 Phishing Website Detection</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Using NLP and machine learning to detect phishing websites.</p>", unsafe_allow_html=True)

   
    st.image("logo.webp") 
   

    classifier = load_model()
    if classifier is None:
        st.stop() 

    url = st.text_input("Enter the website URL to check:")

    if url and validators.url(url):
        protocol, domain, subdomain = extract_domain_info(url)

        result, confidence = detect_phishing(classifier, domain)

        domain_info = get_domain_info(domain)
        if domain_info:
            domain_age = domain_info['age']
            st.write(f"**Domain Age**: {domain_age} days")
            if domain_age and domain_age < 180:
                st.warning("⚠️ The domain is less than 6 months old, which is a common trait of phishing sites.")
            st.write(f"**Registrar**: {domain_info['registrar']}")
            st.write(f"**Country**: {domain_info['country']}")
            st.write(f"**Domain Status**: {domain_info['status']}")
            st.write(f"**Expiration Date**: {domain_info['expiration_date']}")
        else:
            st.error("Could not retrieve domain information.")

        st.write(f"**Extracted Domain**: {domain}")
        st.write(f"**Subdomain**: {subdomain if subdomain else 'None'}")
        st.write(f"**Protocol**: {protocol.upper()}")

        if protocol == "https":
            st.success("The website is using HTTPS (Secure)")
        else:
            st.warning("The website is using HTTP (Insecure)")

    if st.button("Detect"):
        if url and validators.url(url):
            protocol, domain, subdomain = extract_domain_info(url)

            result, confidence = detect_phishing(classifier, domain)

           
            st.session_state.history = add_to_history(st.session_state.history, url, domain, result, confidence, domain_info['age'])

            
            st.subheader(f"🔍 The website is classified as: **{result.upper()}**")
            st.subheader(f"Confidence Score: **{confidence:.2f}%**")

            if result == "phishing":
                st.error("⚠️ Warning: This site seems to be a phishing attempt!")
            else:
                st.success("✅ This site is classified as legitimate.")

            st.progress(int(confidence))

            
            fig = plot_pie_chart(result, confidence)
            st.pyplot(fig)

           
            csv = st.session_state.history.to_csv(index=False)
            st.download_button(label="Download History", data=csv, file_name="phishing_detection_history.csv", mime="text/csv")

   
    if not st.session_state.history.empty:
        st.subheader("Previous Scans")
        st.dataframe(st.session_state.history)

    
    st.sidebar.title("About")
    st.sidebar.info("This app uses advanced machine learning models to detect phishing websites based on domain analysis.")


if __name__ == '__main__':
    main()

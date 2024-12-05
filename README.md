# Phishing Website Detection Application

## 🔍 Overview
This **Phishing Website Detection Application** is a machine-learning-powered tool designed to analyze URLs and classify them as phishing or legitimate. Using advanced natural language processing (NLP) techniques, it provides confidence scores and detailed domain information, enabling users to detect potentially malicious websites.

---

## 🛠 Features
- **Phishing Classification**: Detects phishing websites using the `facebook/bart-large-mnli` model for zero-shot classification.
- **Confidence Score**: Displays the confidence percentage for phishing or legitimate predictions.
- **Domain Analysis**: Extracts and displays:
  - Domain age
  - Registrar information
  - Country of registration
  - Domain status and expiration date
- **Protocol Verification**: Highlights whether the URL uses secure `HTTPS` or insecure `HTTP`.
- **Interactive Visualizations**: Pie chart representation of confidence scores.
- **History Management**: Tracks scanned URLs with options to download results as a CSV file.

---

## 🖥️ Technologies Used
- **Streamlit**: For building the interactive web application.
- **Transformers**: Pre-trained NLP models from Hugging Face (`facebook/bart-large-mnli`).
- **WHOIS**: To fetch domain registration and age information.
- **Matplotlib**: For plotting visualizations.
- **Pandas**: For managing historical scan data.
- **TLDExtract**: To parse and extract URL components.

---

## 🚀 How to Run the Project

### Prerequisites
- **Python 3.7 or above**.
- Required Python packages (install via `pip`):
  ```bash
  pip install streamlit transformers tldextract validators whois matplotlib pandas
  ```

### Running the Application
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo-name/phishing-website-detection.git
   ```
2. Navigate to the project directory:
   ```bash
   cd phishing-website-detection
   ```
3. Launch the Streamlit app:
   ```bash
   streamlit run Phishing_Website_app.py
   ```
4. Open the displayed URL in your browser (usually `http://localhost:8501`).

---

## 🧰 How It Works
1. Enter the URL you want to analyze in the input box.
2. Click **Detect** to classify the URL.
3. The app will:
   - Extract and display domain details.
   - Check the protocol (HTTP/HTTPS).
   - Use the ML model to predict phishing or legitimate.
   - Display confidence scores and additional domain info.
4. Review results in the **Previous Scans** section and download history as a CSV if needed.

---

## 📂 Project Structure
```
phishing-website-detection/
│
├── Phishing_Website_app.py       # Main application script
├── logo.png                      # Logo displayed in the app (optional)
├── requirements.txt              # List of dependencies
└── README.md                     # Documentation file (this file)
```

---

## 📊 Example Output
### Domain Details:
- **Extracted Domain**: example.com  
- **Protocol**: HTTPS  
- **Domain Age**: 365 days  

### Prediction:
- **Classification**: Phishing  
- **Confidence**: 89.75%  

### Visualization:
![Pie Chart Example](link_to_image_or_placeholder)

---

## 📜 License
This project is open-source and available under the [MIT License](LICENSE).

---

## 🛡️ Disclaimer
This application is intended for educational purposes only and should not be used as a substitute for professional security tools.

---

## 🙌 Contributing
We welcome contributions! Please fork the repository, make changes, and submit a pull request.

---

## 📧 Contact
For queries or suggestions, feel free to reach out:
- **Email**: [rajaccet28@gmail.com](mailto:rajaccet28@gmail.com)  
- **Instagram**: [@iamraja.28](https://instagram.com/iamraja.28)

--- 

Let me know if you'd like further edits!

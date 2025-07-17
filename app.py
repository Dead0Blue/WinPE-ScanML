import streamlit as st
import pandas as pd
import numpy as np
import joblib
import hashlib
import time
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import matplotlib.pyplot as plt
from io import BytesIO

# Page configuration
st.set_page_config(
    page_title="Malware Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state for threat tracking
if 'threat_stats' not in st.session_state:
    st.session_state.threat_stats = {
        'total_files': 0,
        'malicious_count': 0,
        'benign_count': 0,
        'recent_files': []
    }

# Load model and artifacts
@st.cache_resource
def load_model():
    try:
        model = joblib.load('model_artifacts/modele_regression_logistique.pkl')
        scaler = joblib.load('model_artifacts/scaler.pkl')
        feature_columns = joblib.load('model_artifacts/features_columns.pkl')
        # Load sample database (replace with your actual training data)
        db = pd.read_csv('sample_database.csv')  
        return model, scaler, feature_columns, db
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        st.stop()

model, scaler, feature_columns, database = load_model()

# Email configuration
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "your_email@example.com"
SMTP_PASSWORD = "your_password"

# Hash calculation functions
def calculate_sha256(file):
    file.seek(0)
    return hashlib.sha256(file.read()).hexdigest()

def calculate_md5(file):
    file.seek(0)
    return hashlib.md5(file.read()).hexdigest()

# Email alert function
def send_email_alert(file_name, result, confidence, recipient):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = recipient
        msg['Subject'] = f"Malware Detection Alert: {file_name}"
        
        body = f"""
        <h2>Malware Detection Results</h2>
        <p><strong>File Name:</strong> {file_name}</p>
        <p><strong>Status:</strong> {'MALICIOUS 🚨' if result == 1 else 'BENIGN ✅'}</p>
        <p><strong>Confidence:</strong> {confidence:.2%}</p>
        <p><strong>Detection Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        """
        msg.attach(MIMEText(body, 'html'))
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
            
        return True
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")
        return False

# Main application
st.title("🛡️ Windows PE Static Malware Detection")
st.markdown("""
This AI-powered system detects malware in Windows Portable Executable (PE) files using static analysis.
Upload a Windows executable file (EXE/DLL) to analyze it for malware.
""")

# Sidebar with info
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/1/1f/Windows_Security_icon.png/64px-Windows_Security_icon.png", width=80)
    st.header("About")
    st.markdown("""
    This application uses a machine learning model trained on:
    - 5,000 PE files
    - Logistic Regression algorithm
    - Static analysis features
    
    **Model Performance:**
    - Accuracy: 99.5%
    - AUC ROC: 0.9976
    """)
    st.divider()
    st.markdown("Developed by Your Name")
    st.markdown("[GitHub Repository](https://github.com/Dead0Blue/AI-Assisted-Windows-PE-Static-Malware-Analysis)")

# Tabs for different functionalities
tab1, tab2, tab3 = st.tabs(["File Analysis", "Threat Dashboard", "Email Settings"])

# Tab 1: File Analysis
with tab1:
    st.subheader("Analyze PE File")
    uploaded_file = st.file_uploader("Upload a Windows executable (EXE/DLL)", type=["exe", "dll"])
    
    if uploaded_file is not None:
        with st.spinner('Analyzing file...'):
            # Calculate hashes
            sha256 = calculate_sha256(uploaded_file)
            md5 = calculate_md5(uploaded_file)
            
            # Look up hash in database
            file_record = database[(database['sha256'] == sha256) | (database['md5'] == md5)]
            
            if not file_record.empty:
                # Preprocess and predict
                processed_data = preprocess_data(file_record)
                prediction = model.predict(processed_data)[0]
                probability = model.predict_proba(processed_data)[0][1]
                
                # Update threat stats
                st.session_state.threat_stats['total_files'] += 1
                if prediction == 1:
                    st.session_state.threat_stats['malicious_count'] += 1
                    status = "Malicious 🚨"
                else:
                    st.session_state.threat_stats['benign_count'] += 1
                    status = "Benign ✅"
                
                # Add to recent files
                st.session_state.threat_stats['recent_files'].insert(0, {
                    'name': uploaded_file.name,
                    'time': datetime.now(),
                    'status': status,
                    'confidence': probability
                })
                
                # Keep only last 5 entries
                st.session_state.threat_stats['recent_files'] = st.session_state.threat_stats['recent_files'][:5]
                
                # Display results
                st.subheader("Analysis Results")
                col1, col2 = st.columns(2)
                col1.metric("Status", status)
                col2.metric("Malware Confidence", f"{probability:.2%}")
                
                st.divider()
                st.subheader("File Information")
                st.text(f"File Name: {uploaded_file.name}")
                st.text(f"SHA256: {sha256}")
                st.text(f"MD5: {md5}")
                st.text(f"Size: {len(uploaded_file.getvalue()) / 1024:.2f} KB")
            else:
                st.warning("File hash not found in malware database")
                st.text(f"SHA256: {sha256}")
                st.text(f"MD5: {md5}")

# Tab 2: Threat Dashboard
with tab2:
    st.subheader("Real-time Threat Dashboard")
    
    # Display stats cards
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Files Analyzed", st.session_state.threat_stats['total_files'])
    col2.metric("Malicious Files", st.session_state.threat_stats['malicious_count'])
    col3.metric("Benign Files", st.session_state.threat_stats['benign_count'])
    
    # Threat distribution chart
    st.subheader("Threat Distribution")
    if st.session_state.threat_stats['total_files'] > 0:
        fig, ax = plt.subplots()
        ax.pie(
            [st.session_state.threat_stats['malicious_count'], 
             st.session_state.threat_stats['benign_count']],
            labels=['Malicious', 'Benign'],
            colors=['#ff4b4b', '#00cc96'],
            autopct='%1.1f%%',
            startangle=90
        )
        ax.axis('equal')
        st.pyplot(fig)
    else:
        st.info("No files analyzed yet")
    
    # Recent files table
    st.subheader("Recent Files Analyzed")
    if st.session_state.threat_stats['recent_files']:
        recent_df = pd.DataFrame(st.session_state.threat_stats['recent_files'])
        st.dataframe(recent_df.style.format({'confidence': '{:.2%}'}), hide_index=True)
    else:
        st.info("No recent files analyzed")

# Tab 3: Email Settings
with tab3:
    st.subheader("Email Alert Configuration")
    email = st.text_input("Enter your email for threat alerts")
    enable_alerts = st.checkbox("Enable email alerts for malicious files")
    
    if st.button("Save Configuration"):
        st.session_state.email = email
        st.session_state.enable_alerts = enable_alerts
        st.success("Configuration saved!")
    
    if 'enable_alerts' in st.session_state and st.session_state.enable_alerts:
        st.info(f"Alerts enabled for: {st.session_state.email}")

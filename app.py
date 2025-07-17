import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
from datetime import datetime
import os

# Page configuration
st.set_page_config(
    page_title="Malware Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
 
# Load model and artifacts
@st.cache_resource
def load_model():
    try:
        model = joblib.load('model_artifacts/modele_regression_logistique.pkl')
        scaler = joblib.load('model_artifacts/scaler.pkl')
        feature_columns = joblib.load('model_artifacts/features_columns.pkl')
        return model, scaler, feature_columns
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        st.stop()

model, scaler, feature_columns = load_model()

# Preprocessing functions
def convert_appeared(date_str):
    try:
        if isinstance(date_str, str):
            return datetime.strptime(date_str + '-01', '%Y-%m-%d').timestamp()
        else:
            return np.nan
    except:
        return np.nan

def preprocess_data(df):
    """Preprocess input data to match training format"""
    # Create a copy to avoid modifying original
    processed = df.copy()
    
    # Drop unnecessary columns
    if 'sha256' in processed.columns:
        processed = processed.drop('sha256', axis=1)
    if 'md5' in processed.columns:
        processed = processed.drop('md5', axis=1)
    
    # Convert appeared column
    if 'appeared' in processed.columns:
        processed['appeared'] = processed['appeared'].apply(convert_appeared)
        appeared_median = processed['appeared'].median()
        processed['appeared'] = processed['appeared'].fillna(appeared_median)
    
    # Process numeric columns
    numeric_cols = ['exports', 'datadirectories']
    for col in numeric_cols:
        if col in processed.columns:
            processed[col] = pd.to_numeric(processed[col], errors='coerce')
            col_median = processed[col].median()
            processed[col] = processed[col].fillna(col_median)
    
    # Process categorical columns
    if 'avclass' in processed.columns:
        processed['avclass'] = processed['avclass'].fillna('missing')
    
    # Process complex columns
    complex_cols = ['histogram', 'byteentropy', 'strings', 'general', 'header', 'section', 'imports']
    for col in complex_cols:
        if col in processed.columns:
            processed[col] = processed[col].astype(str)
            processed[col] = processed[col].apply(lambda x: x[:50] + '...' if len(x) > 50 else x)
    
    # Create dummies
    categorical_cols = ['avclass'] + complex_cols
    processed = pd.get_dummies(processed, columns=categorical_cols, drop_first=True)
    
    # Ensure all columns from training are present
    for col in feature_columns:
        if col not in processed.columns:
            processed[col] = 0
    
    # Reorder columns to match training
    processed = processed[feature_columns]
    
    # Scale the data
    processed_scaled = scaler.transform(processed)
    
    # Replace NaNs with 0
    processed_scaled = np.nan_to_num(processed_scaled, nan=0.0)
    
    return processed_scaled

# Main application
st.title("🛡️ Windows PE Static Malware Detection")
st.markdown("""
This AI-powered system detects malware in Windows Portable Executable (PE) files using static analysis features.
Upload a CSV or Excel file containing PE file features to get predictions.
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

# File upload section
uploaded_file = st.file_uploader("Upload your PE features file (CSV or Excel)", type=["csv", "xlsx"])

if uploaded_file is not None:
    try:
        # Read file
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file, engine='openpyxl')
        
        # Show preview
        st.subheader("Uploaded Data Preview")
        st.dataframe(df.head(3))
        
        # Preprocess and predict
        with st.spinner('Processing and predicting...'):
            # Preprocess
            processed_data = preprocess_data(df)
            
            # Predict
            predictions = model.predict(processed_data)
            probabilities = model.predict_proba(processed_data)[:, 1]
            
            # Create results dataframe
            results = df.copy()
            results['Prediction'] = predictions
            results['Malware Probability'] = probabilities
            results['Status'] = results['Prediction'].apply(lambda x: 'Malicious 🚨' if x == 1 else 'Benign ✅')
            
            # Show results
            st.subheader("Prediction Results")
            st.dataframe(results[['Status', 'Malware Probability']].style.format({'Malware Probability': '{:.2%}'}), height=300)
            
            # Download results
            csv = results.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="Download Predictions as CSV",
                data=csv,
                file_name='malware_predictions.csv',
                mime='text/csv'
            )
            
            # Show stats
            malware_count = results['Prediction'].sum()
            total_count = len(results)
            st.metric("Malicious Files Detected", f"{malware_count}/{total_count} ({malware_count/total_count:.1%})")
            
            # Show distribution
            chart_data = results['Status'].value_counts().reset_index()
            chart_data.columns = ['Status', 'Count']
            st.bar_chart(chart_data.set_index('Status'))
            
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        st.stop()

else:
    # Show sample input format
    st.subheader("Expected Input Format")
    st.markdown("""
    Your input file should contain the following columns:
    - `appeared`: Date string (e.g., "2018-11")
    - `avclass`: AV classification (string)
    - `histogram`, `byteentropy`, `strings`, `general`, `header`, `section`, `imports`: Feature data
    - `exports`, `datadirectories`: Numeric values
    
    Optional columns: `sha256`, `md5`
    """)
    
    # Create a sample dataframe
    sample_data = {
        'appeared': ['2020-01', '2020-02', '2020-03'],
        'avclass': ['Trojan', 'Adware', 'Benign'],
        'histogram': ['hist_data_1', 'hist_data_2', 'hist_data_3'],
        'exports': [5, 8, 3],
        'datadirectories': [12, 15, 10]
    }
    sample_df = pd.DataFrame(sample_data)
    
    st.dataframe(sample_df)
    
    # Download sample template
    csv = sample_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Sample Template",
        data=csv,
        file_name='malware_template.csv',
        mime='text/csv'
    )

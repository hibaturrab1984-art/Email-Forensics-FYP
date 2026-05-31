#!/usr/bin/env python
# coding: utf-8

# In[48]:


import pickle
from tensorflow.keras.models import load_model

kaggle_model = load_model("best_kaggle_model.keras")
trap_model = load_model("trap4phish_model.keras")
spam_model = load_model("spamassassin_model.keras")

with open("kaggle_tokenizer.pkl", "rb") as f:
    kaggle_tokenizer = pickle.load(f)

with open("spamassassin_tokenizer.pkl", "rb") as f:
    spam_tokenizer = pickle.load(f)

with open("trap4phish_scaler.pkl", "rb") as f:
    trap_scaler = pickle.load(f)

print("All models and preprocessing files loaded successfully.")


# In[49]:


from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np


# In[50]:


def predict_kaggle_email(email_text):
    seq = kaggle_tokenizer.texts_to_sequences([email_text])
    padded = pad_sequences(seq, maxlen=200)
    prob = float(kaggle_model.predict(padded)[0][0])
    if prob >= 0.5:
        label = "Phishing"
    else:
        label = "Legitimate"
    return {
        "model": "Kaggle Phishing Model",
        "prediction": label,
        "confidence_score": max(prob, 1 - prob)
    }


# In[51]:


sample_email = "Your account has been suspended. Click this link immediately to verify your password."
# predict_kaggle_email(sample_email)


# In[52]:


from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np


# In[53]:


def predict_spamassassin_email(email_text):
    seq = spam_tokenizer.texts_to_sequences([email_text])
    padded = pad_sequences(seq, maxlen=200)
    prob = float(spam_model.predict(padded)[0][0])
    print("SpamAssassin raw probability:", prob)
    if prob >= 0.5:
        label = "Legitimate"
    else:
        label = "Spam/Phishing"
    return {
        "model": "SpamAssassin Model",
        "prediction": label,
        "confidence_score": max(prob, 1 - prob)
    }


# In[54]:


# predict_spamassassin_email(sample_email)


# ## Trap4Phish Integration
# 
# Trap4Phish uses spreadsheet/macro-based numerical features, so a real Trap4Phish feature vector is used for integration testing. Raw SpamAssassin emails do not contain these spreadsheet feature values directly.

# In[55]:


import pandas as pd

def predict_trap4phish(features):

    features_df = pd.DataFrame(
        [features],
        columns=trap_scaler.feature_names_in_
    )

    features_scaled = trap_scaler.transform(features_df)

    prob = float(trap_model.predict(features_scaled)[0][0])

    if prob >= 0.5:
        label = "Phishing"
    else:
        label = "Legitimate"

    return {
        "model": "Trap4Phish Model",
        "prediction": label,
        "confidence_score": max(prob, 1 - prob)
    }


# In[33]:


sample_features = [0.2] * 10
# predict_trap4phish(sample_features)


# In[100]:

import re
def detect_phishing_indicators(email_text):
    text = email_text.lower()
    indicators = []
    suspicious_keywords = [
        "verify your account",
        "account suspended",
        "click the link",
        "immediately",
        "password",
        "failure to verify",
        "account closure",
        "login",
        "bank"
    ]
    for word in suspicious_keywords:
        if word in text:
            indicators.append(f"Suspicious keyword found: {word}")
    urls = re.findall(r"http[s]?://\S+", email_text)
    for url in urls:
        if "fake" in url.lower() or "login" in url.lower() or "verify" in url.lower():
            indicators.append(f"Suspicious URL found: {url}")
    return indicators

def analyze_email_text(email_text, trap_features=None):
    kaggle_result = predict_kaggle_email(email_text)
    spam_result = predict_spamassassin_email(email_text)

    results = {
        "email_text": email_text,
        "kaggle_model_result": kaggle_result,
        "spamassassin_model_result": spam_result
    }

    if trap_features is not None:
        trap_result = predict_trap4phish(trap_features)
        results["trap4phish_model_result"] = trap_result
    else:
        trap_result = None

    phishing_votes = 0
    legitimate_votes = 0
    borderline_models = []
    phishing_indicators = detect_phishing_indicators(email_text)

    if kaggle_result["prediction"] == "Phishing":
        phishing_votes += 1
    else:
        legitimate_votes += 1

    if 0.45 <= kaggle_result["confidence_score"] <= 0.55:
        borderline_models.append("Kaggle")

    if spam_result["prediction"] == "Spam/Phishing":
        phishing_votes += 1
    else:
        legitimate_votes += 1

    if 0.45 <= spam_result["confidence_score"] <= 0.55:
        borderline_models.append("SpamAssassin")

    if trap_result is not None:
        if trap_result["prediction"] == "Phishing":
            phishing_votes += 1
        else:
            legitimate_votes += 1

        if 0.45 <= trap_result["confidence_score"] <= 0.55:
            borderline_models.append("Trap4Phish")

    if len(phishing_indicators) >= 2:
        final_verdict = "Suspicious / Potential Phishing"

    elif phishing_votes > legitimate_votes:
        final_verdict = "Suspicious / Potential Phishing"

    elif legitimate_votes > phishing_votes:
        final_verdict = "Likely Legitimate"

    elif phishing_votes == legitimate_votes:
        if kaggle_result["prediction"] == "Phishing" and kaggle_result["confidence_score"] >= 0.80:
            final_verdict = "Suspicious / Potential Phishing"
        elif kaggle_result["prediction"] == "Legitimate" and kaggle_result["confidence_score"] >= 0.80:
            final_verdict = "Likely Legitimate"
        elif any("URL" in indicator for indicator in phishing_indicators):
            final_verdict = "Suspicious / Potential Phishing"
        elif len(phishing_indicators) >= 2:
            final_verdict = "Suspicious / Potential Phishing"
        else:
            final_verdict = "Requires Manual Review"

    results["phishing_votes"] = phishing_votes
    results["legitimate_votes"] = legitimate_votes
    results["borderline_models"] = borderline_models
    results["phishing_indicators"] = phishing_indicators
    results["final_verdict"] = final_verdict

    return results   

    
# In[101]:


# analyze_email_text(sample_email)


# In[57]:


def generate_forensic_report(email_text):
    analysis = analyze_email_text(email_text)
    print("====== EMAIL FORENSIC REPORT ======")
    print()
    print("Email Content:")
    print(email_text)
    print()
    print("Kaggle Model Prediction:")
    print(analysis["kaggle_model_result"])
    print()
    print("SpamAssassin Model Prediction:")
    print(analysis["spamassassin_model_result"])
    print()
    print("Final Verdict:")
    print(analysis["final_verdict"])


# In[37]:


# generate_forensic_report(sample_email)


# In[58]:


def generate_full_report(email_text, trap_features=None):
    text_analysis = analyze_email_text(email_text)
    print("====== EMAIL FORENSIC REPORT ======")
    print("Email Content:")
    print(email_text)
    print()
    print("Kaggle Model Prediction:")
    print(text_analysis["kaggle_model_result"])
    print()
    print("SpamAssassin Model Prediction:")
    print(text_analysis["spamassassin_model_result"])
    print()
    if trap_features is not None:
        trap_result = predict_trap4phish(trap_features)
        print("Trap4Phish Model Prediction:")
        print(trap_result)
        print()
    print("Final Verdict:")
    print(text_analysis["final_verdict"])


# In[88]:


# generate_full_report(sample_email, sample_features)


# In[60]:


from email import message_from_string
from email.policy import default

def parse_email(raw_email):
    msg = message_from_string(raw_email, policy=default)

    parsed_data = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "return_path": msg.get("Return-Path"),
        "received_headers": msg.get_all("Received", []),
        "authentication_results": msg.get("Authentication-Results")
    }

    return parsed_data


# In[43]:


email_path = "Datasets/spamassassin/20021010_spam/spam/0498.863566df8e5f17f979edca79d1e87187"

with open(email_path, "r", encoding="latin-1") as f:
    raw_email = f.read()

parse_email(raw_email)


# In[61]:


def analyze_headers(parsed_email):
    findings = []

    auth_results = parsed_email.get("authentication_results")
    received_headers = parsed_email.get("received_headers", [])
    return_path = parsed_email.get("return_path")

    if return_path:
        findings.append("Return-Path found")
    else:
        findings.append("Return-Path not found")

    if received_headers:
        findings.append(f"{len(received_headers)} Received headers detected")
    else:
        findings.append("No Received headers detected")

    if auth_results:
        auth_lower = auth_results.lower()

        if "spf=pass" in auth_lower:
            findings.append("SPF authentication passed")
        elif "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
            findings.append("SPF authentication failed or softfailed")
        else:
            findings.append("SPF result not clearly found")

        if "dkim=pass" in auth_lower:
            findings.append("DKIM authentication passed")
        elif "dkim=fail" in auth_lower:
            findings.append("DKIM authentication failed")
        else:
            findings.append("DKIM result not clearly found")

        if "dmarc=pass" in auth_lower:
            findings.append("DMARC authentication passed")
        elif "dmarc=fail" in auth_lower:
            findings.append("DMARC authentication failed")
        else:
            findings.append("DMARC result not clearly found")
    else:
        findings.append("No SPF/DKIM/DMARC authentication results present")

    return findings
    


# In[45]:


parsed_email = parse_email(raw_email)
analyze_headers(parsed_email)


# In[102]:




# In[103]:


# report = generate_integrated_report(raw_email, sample_features)


# In[72]:


from email import policy
from email.parser import Parser

def extract_email_body(raw_email):
    msg = Parser(policy=policy.default).parsestr(raw_email)

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    return part.get_content()
                except:
                    payload = part.get_payload(decode=True)
                    return payload.decode("latin-1", errors="ignore")

            if content_type == "text/html":
                try:
                    return part.get_content()
                except:
                    payload = part.get_payload(decode=True)
                    return payload.decode("latin-1", errors="ignore")

    else:
        try:
            return msg.get_content()
        except:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode("latin-1", errors="ignore")
            return str(msg.get_payload())

    return ""


# In[ ]:


# email_body = extract_email_body(raw_email)
# print(email_body[:1000])


# In[ ]:


import subprocess
# subprocess.check_call(["pip", "install", "beautifulsoup4"])


# In[73]:


from bs4 import BeautifulSoup
def clean_email_body(raw_email):
    body = extract_email_body(raw_email)
    soup = BeautifulSoup(body, "html.parser")
    clean_text = soup.get_text(separator=" ", strip=True)
    return clean_text


# In[74]:



# clean_body = clean_email_body(raw_email)
# print(clean_body[:1000])


# In[ ]:


# print(clean_email_body(raw_email)[:300])


# ## Integrated Email Forensic Analysis Pipeline
# 
# This module integrates email parsing, header analysis, machine learning-based phishing detection, and forensic verdict generation into a single investigation workflow.

# In[ ]:


def generate_integrated_report(raw_email, trap_features=None):
    parsed_email = parse_email(raw_email)
    header_findings = analyze_headers(parsed_email)
    email_text = clean_email_body(raw_email)
    ml_analysis = analyze_email_text(email_text, trap_features)

    report = {
        "parsed_email": parsed_email,
        "header_findings": header_findings,
        "email_text": email_text,
        "kaggle_model_result": ml_analysis["kaggle_model_result"],
        "spamassassin_model_result": ml_analysis["spamassassin_model_result"],
        "phishing_votes": ml_analysis["phishing_votes"],
        "legitimate_votes": ml_analysis["legitimate_votes"],
        "borderline_models": ml_analysis["borderline_models"],
        "phishing_indicators": ml_analysis["phishing_indicators"],
        "final_verdict": ml_analysis["final_verdict"]
    }

    if "trap4phish_model_result" in ml_analysis:
        report["trap4phish_model_result"] = ml_analysis["trap4phish_model_result"]

    return report

# In[ ]:


# generate_integrated_report(raw_email, sample_features)


# In[ ]:


import pandas as pd

trap_df = pd.read_csv("Datasets/Trap4phish/Trap4phish.csv")
trap_df.head()


# In[ ]:


trap_df.columns


# In[ ]:


feature_cols = [
    "entropy_of_text",
    "macro_chr_count",
    "macro_vocab_size",
    "macro_arithmetic_operator_count",
    "macro_token_count",
    "macro_max_line_length",
    "remote_template_present",
    "numeric_cell_count",
    "string_cell_count",
    "avg_cell_length"
]

sample_features = trap_df.loc[0, feature_cols].tolist()

sample_features


# In[ ]:


type(trap_scaler)


# In[ ]:


trap_scaler.feature_names_in_


# In[ ]:


import os

spam_folder = "Datasets/spamassassin/20021010_spam/spam"



# print("Total spam emails:", len(os.listdir(spam_folder)))


# In[ ]:


spam_files = os.listdir(spam_folder)[:5]
"""
for file in spam_files:
    print("\n==============================")
    print("Testing file:", file)

    email_path = os.path.join(spam_folder, file)

    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    # generate_integrated_report(raw_email, sample_features)


# In[ ]:


trap_df.head(1).T


# In[ ]:


ham_folder = "Datasets/spamassassin/20021010_easy_ham/easy_ham"

import os
print("Total legitimate emails:", len(os.listdir(ham_folder)))


# In[ ]:


ham_files = os.listdir(ham_folder)[:5]

for file in ham_files:
    print("\n==============================")
    print("Testing file:", file)

    email_path = os.path.join(ham_folder, file)

    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    # generate_integrated_report(raw_email, sample_feature)


# In[ ]:


ham_files = os.listdir(ham_folder)[:5]

legit_count = 0
phish_count = 0

for file in ham_files:
    email_path = os.path.join(ham_folder, file)

    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    result = generate_integrated_report(raw_email, sample_features)

    if result["final_verdict"] == "Legitimate":
        legit_count += 1
    else:
        phish_count += 1

print("Legitimate:", legit_count)
print("Suspicious:", phish_count)


# In[ ]:


result = generate_integrated_report(raw_email, sample_features)

type(result)


# In[ ]:


from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


# In[ ]:


test_results = []

def get_integrated_label(raw_email):
    result = generate_integrated_report(raw_email, sample_features)
    return result["final_verdict"]

# 10 spam emails
for file in os.listdir(spam_folder)[:10]:
    email_path = os.path.join(spam_folder, file)
    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    pred = get_integrated_label(raw_email)
    test_results.append(["spam", pred])

# 10 legitimate emails
for file in os.listdir(ham_folder)[:10]:
    email_path = os.path.join(ham_folder, file)
    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    pred = get_integrated_label(raw_email)
    test_results.append(["legitimate", pred])

test_results


# In[ ]:


model_test_results = []

for file in os.listdir(spam_folder)[:10]:
    path = os.path.join(spam_folder, file)
    with open(path, "r", encoding="latin-1") as f:
        raw_email = f.read()
    body = clean_email_body(raw_email)

    kag = predict_kaggle_email(body)["prediction"]
    spam = predict_spamassassin_email(body)["prediction"]

    model_test_results.append(["spam", kag, spam])

for file in os.listdir(ham_folder)[:10]:
    path = os.path.join(ham_folder, file)
    with open(path, "r", encoding="latin-1") as f:
        raw_email = f.read()
    body = clean_email_body(raw_email)

    kag = predict_kaggle_email(body)["prediction"]
    spam = predict_spamassassin_email(body)["prediction"]

    model_test_results.append(["legitimate", kag, spam])

model_test_results


# In[ ]:


import pandas as pd
results_df = pd.DataFrame(
    model_test_results,
    columns=["Actual", "Kaggle", "SpamAssassin"]
)
results_df.head()


# In[ ]:


results_df


# In[ ]:


from sklearn.metrics import accuracy_score

kaggle_correct = (
    ((results_df["Actual"] == "spam") & (results_df["Kaggle"] == "Phishing")) |
    ((results_df["Actual"] == "legitimate") & (results_df["Kaggle"] == "Legitimate"))
)

spam_correct = (
    ((results_df["Actual"] == "spam") & (results_df["SpamAssassin"] == "Spam/Phishing")) |
    ((results_df["Actual"] == "legitimate") & (results_df["SpamAssassin"] == "Legitimate"))
)

print("Kaggle Accuracy:", kaggle_correct.mean())
print("SpamAssassin Accuracy:", spam_correct.mean())


# In[ ]:


len(results_df)


# In[ ]:


results = []

spam_files = os.listdir(spam_folder)[:100]
ham_files = os.listdir(ham_folder)[:100]

for file in spam_files:
    email_path = os.path.join(spam_folder, file)

    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    result = generate_integrated_report(raw_email, sample_features)

    results.append(["spam", result["final_verdict"]])

for file in ham_files:
    email_path = os.path.join(ham_folder, file)

    with open(email_path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    result = generate_integrated_report(raw_email, sample_features)

    results.append(["legitimate", result["final_verdict"]])

results_df = pd.DataFrame(results, columns=["Actual", "Prediction"])

results_df.head()


# In[ ]:


kaggle_results = []

for file in os.listdir(spam_folder)[:100]:
    path = os.path.join(spam_folder, file)
    with open(path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    body = clean_email_body(raw_email)
    pred = predict_kaggle_email(body)["prediction"]
    kaggle_results.append(["spam", pred])

for file in os.listdir(ham_folder)[:100]:
    path = os.path.join(ham_folder, file)
    with open(path, "r", encoding="latin-1") as f:
        raw_email = f.read()

    body = clean_email_body(raw_email)
    pred = predict_kaggle_email(body)["prediction"]
    kaggle_results.append(["legitimate", pred])

kaggle_df = pd.DataFrame(kaggle_results, columns=["Actual", "Prediction"])
kaggle_df.head()


# In[ ]:


kaggle_df["Prediction"].value_counts()


# In[ ]:


pd.crosstab(kaggle_df["Actual"], kaggle_df["Prediction"])


# In[ ]:


from sklearn.metrics import classification_report

y_true = ["Phishing" if x=="spam" else "Legitimate"
          for x in kaggle_df["Actual"]]

print(classification_report(
    y_true,
    kaggle_df["Prediction"]
))
"""

# In[75]:


# generate_integrated_report(raw_email, sample_features)

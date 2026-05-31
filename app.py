import random
import streamlit as st
from integration_pipeline import generate_integrated_report

st.set_page_config(page_title="Email Forensics System", layout="wide")

st.title("Email Forensics: Phishing Detection System")
st.write("Paste a raw email below or let the system load a sample email.")

sample_phishing = """Subject: Verify Your Account

Dear User,

Your account has been suspended.
Click the link below immediately to verify your password:

http://fake-bank-login.com

Failure to verify within 24 hours will result in account closure.

Regards,
Security Team
"""

sample_legitimate = """Subject: Project Meeting Update

Dear Team,

This is a reminder that our project meeting is scheduled for tomorrow at 10 AM.
Please review the agenda before the meeting.

Regards,
Project Coordinator
"""

input_source = st.selectbox(
    "Email Input Source",
    ["Manual Input", "Load Sample Email"]
)

if input_source == "Load Sample Email":
    if "sample_email" not in st.session_state:
        st.session_state.sample_email = random.choice([sample_phishing, sample_legitimate])

    if st.button("🔄 New Sample"):
        st.session_state.sample_email = random.choice([sample_phishing, sample_legitimate])
        st.rerun()

    raw_email = st.text_area(
        "Raw Email Content",
        value=st.session_state.sample_email,
        height=300
    )

else:
    if "email_box" not in st.session_state:
        st.session_state.email_box = ""

    if st.button("🔄 New Input"):
        st.session_state.email_box = ""
        st.rerun()

    raw_email = st.text_area(
        "Raw Email Content",
        key="email_box",
        height=300
    )

if st.button("Analyze Email"):
    if raw_email.strip() == "":
        st.warning("Please paste or load an email first.")
    else:
        st.info("Analyzing email...")

        report = generate_integrated_report(raw_email)

        st.subheader("Final Verdict")
        st.success(report["final_verdict"])

        st.subheader("Parsed Email Details")
        st.json(report["parsed_email"])

        st.subheader("Header Analysis Findings")
        for finding in report["header_findings"]:
            st.write(f"- {finding}")

        st.subheader("ML Model Results")

        st.write("Kaggle:")
        st.json(report["kaggle_model_result"])

        st.write("SpamAssassin:")
        st.json(report["spamassassin_model_result"])

        if "trap4phish_model_result" in report:
            st.write("Trap4Phish:")
            st.json(report["trap4phish_model_result"])
        else:
            st.write("Trap4Phish: Not applied for manual text input")

        st.subheader("Phishing Indicators")
        if report["phishing_indicators"]:
            for indicator in report["phishing_indicators"]:
                st.write(f"- {indicator}")
        else:
            st.write("No phishing indicators found.")

        st.subheader("Decision Summary")
        st.write("Phishing Votes:", report["phishing_votes"])
        st.write("Legitimate Votes:", report["legitimate_votes"])
        st.write("Borderline Models:")
        st.json(report["borderline_models"])
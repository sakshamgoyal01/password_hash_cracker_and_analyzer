# app.py

import streamlit as st
import pandas as pd
import string
import itertools
from app.hash_analyzer import identify_hash_type
from app.hash_cracker import (
    crack_md5, crack_ntlm, crack_sha1, crack_sha256, crack_bcrypt, brute_force_crack, crack_sha512
)

st.set_page_config(page_title="🔐 Multi-Hash Cracker", layout="wide")
st.title("🔐 Multi-Hash Cracker + Analyzer")
st.markdown("**Supports:** `MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `bcrypt`, `NTLM`  \n**Wordlist used:** `rockyou.txt`")

wordlist_path = "rockyou.txt"

# Tabs for organization
tab1, tab2 = st.tabs(["🔍 Single Hash", "📁 Multiple Hashes"])

with tab1:
    st.header("🔍 Analyze and Crack a Single Hash")
    st.markdown("Enter a hash below to analyze and attempt to crack it:")

    with st.form("single_hash_form"):
        hash_input = st.text_input("Enter a hash")
        submitted = st.form_submit_button("Crack Hash")

    if submitted:
        if not hash_input:
            st.warning("⚠️ Please enter a hash.")
        else:
            hash_type = identify_hash_type(hash_input)
            st.info(f"🧬 Detected Hash Type: **{hash_type}**")

            result = None
            if hash_type == "MD5":
                result = crack_md5(hash_input, wordlist_path)
            elif hash_type == "SHA-1":
                result = crack_sha1(hash_input, wordlist_path)
            elif hash_type == "SHA-256":
                result = crack_sha256(hash_input, wordlist_path)
            elif hash_type == "SHA-512":
                result = crack_sha512(hash_input, wordlist_path)
            elif hash_type == "bcrypt":
                result = crack_bcrypt(hash_input, wordlist_path)
            elif hash_type == "NTLM":
                result = crack_ntlm(hash_input, wordlist_path)

            if result:
                st.success(f"✅ Password Found: **{result}**")
            else:
                st.warning("🔍 Not found in wordlist. Trying brute-force (max 4 chars)...")
                brute_result = brute_force_crack(hash_input, hash_type)
                if brute_result:
                    st.success(f"🚀 Brute-Force Success: **{brute_result}**")
                else:
                    st.error("❌ Password not cracked.")

with tab2:
    st.header("📁 Crack Multiple Hashes from File")
    uploaded_file = st.file_uploader("Upload a text file of hashes (one per line)", type=["txt"])

    if uploaded_file is not None:
        hashes = [line.strip() for line in uploaded_file.readlines()]
        st.success(f"📥 {len(hashes)} hashes loaded.")

        cracked_results = []
        progress = st.progress(0)
        status_text = st.empty()

        for idx, hash_line in enumerate(hashes):
            hash_str = hash_line.decode().strip()
            hash_type = identify_hash_type(hash_str)

            result = None
            if hash_type == "MD5":
                result = crack_md5(hash_str, wordlist_path)
            elif hash_type == "SHA-1":
                result = crack_sha1(hash_str, wordlist_path)
            elif hash_type == "SHA-256":
                result = crack_sha256(hash_str, wordlist_path)
            elif hash_type == "SHA-512":
                result = crack_sha512(hash_str, wordlist_path)
            elif hash_type == "bcrypt":
                result = crack_bcrypt(hash_str, wordlist_path)
            elif hash_type == "NTLM":
                result = crack_ntlm(hash_str, wordlist_path)

            if result:
                cracked_results.append((hash_str, hash_type, result))
            else:
                brute_result = brute_force_crack(hash_str, hash_type)
                if brute_result:
                    cracked_results.append((hash_str, hash_type, f"🔓 Brute: {brute_result}"))
                else:
                    cracked_results.append((hash_str, hash_type, "❌ Not found"))

            progress.progress((idx + 1) / len(hashes))
            status_text.text(f"Processing {idx + 1}/{len(hashes)}...")

        st.success("✅ Cracking complete!")

        df = pd.DataFrame(cracked_results, columns=["Hash", "Type", "Result"])
        st.write("### 🧾 Cracked Results:")
        st.dataframe(df)

        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name='cracked_hashes.csv',
            mime='text/csv'
        )

        st.write("### 📊 Hash Type Distribution")
        st.bar_chart(df["Type"].value_counts())

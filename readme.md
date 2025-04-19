# 🔐 Multi-Hash Cracker + Analyzer

A powerful and user-friendly Streamlit app for identifying and cracking various types of password hashes. Supports both **single** and **bulk** hash cracking with wordlist and brute-force capabilities.

---

## 🚀 Features

- 🔍 Identify hash types (MD5, SHA-1, SHA-256, SHA-512, bcrypt, NTLM)
- 🧠 Crack single hash inputs via wordlist or brute-force (max 4 characters)
- 📁 Upload files with multiple hashes and view cracked results
- 📊 Visual distribution of cracked hash types
- 📥 Export results to CSV
- 🔧 Easy deployment using Docker and Docker Compose

---

## 🛠️ Installation

### 🔧 Local Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/hash-cracker-app.git
   cd hash-cracker-app
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Streamlit app:**
   ```bash
   streamlit run app.py
   ```

---

### 🐳 Docker Deployment

#### Build and run using Docker:

```bash
docker build -t hash-cracker .
docker run -p 8501:8501 hash-cracker
```

#### Using Docker Compose:

```bash
docker-compose up --build
```

The app will be available at [http://localhost:8501](http://localhost:8501)

---

## 📂 Wordlist

Make sure to place a wordlist file named `rockyou.txt` in the root directory of the app.
You can download `rockyou.txt` from:

- Kali Linux (default location: `/usr/share/wordlists/rockyou.txt.gz`)
- Online sources (make sure it's safe and legal)

---

## 📎 File Structure

```
.
├── app.py                # Streamlit UI and logic
├── hash_analyzer.py      # Hash type detection logic
├── hash_cracker.py       # Cracking logic (wordlist + brute-force)
├── rockyou.txt           # Password wordlist
├── requirements.txt      # Python dependencies
├── Dockerfile            # Docker build file
├── docker-compose.yml    # Docker Compose config
└── README.md             # Project documentation
```

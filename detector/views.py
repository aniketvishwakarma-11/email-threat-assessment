from pathlib import Path
import csv

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render

import pandas as pd
import PyPDF2
from google import genai

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

from .forms import MessageForm
from .models import ScanRecord


BASE_DIR = Path(__file__).resolve().parent.parent

POSSIBLE_DATASET_PATHS = [
    BASE_DIR / "emails.csv",
    BASE_DIR / "detector" / "emails.csv",
    BASE_DIR / "emails.xlsx",
    BASE_DIR / "detector" / "emails.xlsx",
]


def load_email_dataset():
    dataset = None
    last_error = None

    for path in POSSIBLE_DATASET_PATHS:
        if not path.exists():
            continue

        try:
            if path.suffix.lower() == ".csv":
                dataset = pd.read_csv(path, encoding="latin1")
            elif path.suffix.lower() in [".xlsx", ".xls"]:
                dataset = pd.read_excel(path)
            else:
                continue

            if dataset is not None and not dataset.empty:
                break
        except Exception as e:
            last_error = e
            dataset = None

    if dataset is None or dataset.empty:
        print("DATASET ERROR:", last_error, flush=True)
        return pd.DataFrame(columns=["text", "spam"])

    dataset.columns = dataset.columns.str.strip()
    lowered = {col.lower(): col for col in dataset.columns}

    if "text" in lowered and "spam" in lowered:
        dataset = dataset.rename(columns={
            lowered["text"]: "text",
            lowered["spam"]: "spam",
        })
    elif "v1" in lowered and "v2" in lowered:
        dataset = dataset.rename(columns={
            lowered["v1"]: "spam",
            lowered["v2"]: "text",
        })
    elif "label" in lowered and "text" in lowered:
        dataset = dataset.rename(columns={
            lowered["label"]: "spam",
            lowered["text"]: "text",
        })
    elif len(dataset.columns) >= 2:
        dataset = dataset.iloc[:, :2]
        dataset.columns = ["spam", "text"]

    if "text" not in dataset.columns or "spam" not in dataset.columns:
        print("DATASET ERROR: Required columns not found.", flush=True)
        return pd.DataFrame(columns=["text", "spam"])

    dataset = dataset[["text", "spam"]].dropna()
    dataset["text"] = dataset["text"].astype(str).str.strip()
    dataset["spam"] = dataset["spam"].astype(str).str.strip().str.lower()
    dataset = dataset[dataset["text"] != ""]

    dataset["spam"] = dataset["spam"].replace({
        "1": "spam",
        "0": "ham",
        "ham ": "ham",
        "spam ": "spam",
    })

    dataset = dataset[dataset["spam"].isin(["spam", "ham"])]

    print("DATASET LOADED", flush=True)
    print("COLUMNS:", dataset.columns.tolist(), flush=True)
    print("LABELS:", dataset["spam"].unique(), flush=True)

    return dataset


dataset = load_email_dataset()

vectorizer = CountVectorizer(stop_words="english")
model = None

if not dataset.empty:
    X = vectorizer.fit_transform(dataset["text"])
    y = dataset["spam"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = MultinomialNB()
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    print(f"EMAIL MODEL ACCURACY: {accuracy:.4f}", flush=True)
else:
    print("MODEL NOT TRAINED: Dataset is empty.", flush=True)



def predict_message(message):
    if model is None:
        return "Ham"

    message = str(message).strip()
    if not message:
        return "Ham"

    message_vector = vectorizer.transform([message])
    prediction = model.predict(message_vector)[0]

    return "Spam" if str(prediction).lower() == "spam" else "Ham"


def _email_confidence(message):
    if model is None:
        return None

    probabilities = model.predict_proba(vectorizer.transform([message]))[0]
    return round(float(max(probabilities)), 4)



def extract_pdf_text(file_obj):
    try:
        reader = PyPDF2.PdfReader(file_obj)
        text_parts = []

        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)

        final_text = "\n".join(text_parts).strip()
        print("EXTRACTED PDF TEXT:", final_text[:1000], flush=True)

        return final_text

    except Exception as e:
        print("PDF TEXT EXTRACTION ERROR:", e, flush=True)
        return ""


def rule_based_pdf_check(pdf_text):
    text = str(pdf_text).lower()

    # STRONG malicious indicators
    malicious_keywords = [
        "payload.exe",
        "cmd /c",
        "powershell",
        "disable antivirus",
        "bypass security",
        "exploit",
        "malware",
        "ransomware",
        "trojan",
        "shellcode",
        "execute payload",
        "download payload",
        "run script",
        "execute script"
    ]

    # medium suspicious indicators
    suspicious_keywords = [
        "verify your account",
        "click here",
        "urgent",
        "bank account",
        "login immediately",
        "password",
        "otp",
        "suspended",
        "payment",
        "account closure",
        "credentials",
        "bank details"
    ]

    # 🔴 PRIORITY: malicious first
    for word in malicious_keywords:
        if word in text:
            print("MALICIOUS KEYWORD MATCH:", word, flush=True)
            return "malicious"

    # 🟡 then suspicious
    for word in suspicious_keywords:
        if word in text:
            print("SUSPICIOUS KEYWORD MATCH:", word, flush=True)
            return "suspicious"

    return "safe"


def pdf_indicators(pdf_text):
    text = str(pdf_text).lower()
    keywords = [
        "payload.exe", "cmd /c", "powershell", "disable antivirus",
        "bypass security", "exploit", "malware", "ransomware", "trojan",
        "shellcode", "execute payload", "download payload", "run script",
        "execute script", "verify your account", "click here", "urgent",
        "bank account", "login immediately", "password", "otp", "suspended",
        "payment", "account closure", "credentials", "bank details",
    ]
    return [keyword for keyword in keywords if keyword in text]


def pdf_threat_detection(pdf_text):
    if not pdf_text or not str(pdf_text).strip():
        print("EMPTY PDF TEXT", flush=True)
        return "suspicious"

    rule_result = rule_based_pdf_check(pdf_text)
    print("RULE-BASED PDF RESULT:", rule_result, flush=True)

    # For project reliability, immediately trust clear rule hits
    if rule_result in ["malicious", "suspicious"]:
        return rule_result

    api_key = getattr(settings, "GEMINI_API_KEY", None)

    if api_key is None:
        print("GEMINI API KEY NOT SET", flush=True)
        return rule_result

    api_key = str(api_key).strip()

    if not api_key or api_key == "PASTE_YOUR_GEMINI_API_KEY_HERE":
        print("INVALID GEMINI API KEY", flush=True)
        return rule_result

    try:
        client = genai.Client(api_key=api_key)

        prompt = f"""
You are a cybersecurity classifier.

Classify the following PDF text into exactly one category:
safe
suspicious
malicious

Rules:
- safe = normal notes, report, study material, invoice, documentation
- suspicious = phishing, urgent warning, account verification, fake payment request, suspicious links
- malicious = malware execution, payload delivery, disable antivirus, exploit code, run dangerous commands

PDF text:
{str(pdf_text)[:3000]}

Return exactly one lowercase word only:
safe
suspicious
malicious
"""

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        output = ""
        if response is not None and getattr(response, "text", None):
            output = response.text.strip().lower()

        print("PDF MODEL RAW OUTPUT:", output, flush=True)

        if output == "malicious":
            return "malicious"
        elif output == "suspicious":
            return "suspicious"
        elif output == "safe":
            return "safe"

        if "malicious" in output:
            return "malicious"
        elif "suspicious" in output:
            return "suspicious"
        elif "safe" in output:
            return "safe"

        print("UNEXPECTED OUTPUT, USING RULE RESULT", flush=True)
        return rule_result

    except Exception as e:
        print("PDF DETECTION ERROR:", e, flush=True)
        return rule_result



def Home(request):
    result = None
    pdf_result = None
    pdf_message = None
    form = MessageForm()

    print("REQUEST METHOD:", request.method, flush=True)

    if request.method == "POST":
        print("POST KEYS:", list(request.POST.keys()), flush=True)
        print("FILES KEYS:", list(request.FILES.keys()), flush=True)

        if "email_check" in request.POST:
            print("EMAIL FORM HIT", flush=True)
            form = MessageForm(request.POST)

            if form.is_valid():
                message = form.cleaned_data["text"]
                result = predict_message(message)
                ScanRecord.objects.create(
                    scan_type=ScanRecord.ScanType.EMAIL,
                    verdict=result.lower(),
                    confidence=_email_confidence(message),
                    input_length=len(message),
                    summary=f"Email classified as {result}.",
                )

        elif "pdf_check" in request.POST:
            print("PDF FORM HIT", flush=True)

            if "pdf_file" not in request.FILES:
                pdf_message = "No PDF uploaded."
            else:
                pdf_file = request.FILES["pdf_file"]

                if not pdf_file.name.lower().endswith(".pdf"):
                    pdf_message = "Upload only PDF files."
                else:
                    pdf_text = extract_pdf_text(pdf_file)

                    if not pdf_text:
                        pdf_result = "suspicious"
                        pdf_message = "Could not extract text from this PDF."
                    else:
                        pdf_result = pdf_threat_detection(pdf_text)
                        pdf_message = f"PDF Threat Result: {pdf_result.upper()}"
                        ScanRecord.objects.create(
                            scan_type=ScanRecord.ScanType.PDF,
                            verdict=pdf_result,
                            input_length=len(pdf_text),
                            indicators=pdf_indicators(pdf_text),
                            summary=f"PDF classified as {pdf_result}.",
                        )

    return render(request, "detector/home.html", {
        "form": form,
        "result": result,
        "pdf_result": pdf_result,
        "pdf_message": pdf_message,
    })


def history(request):
    records = ScanRecord.objects.all()[:100]
    return render(request, "detector/history.html", {"records": records})


def export_history(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="scan-history.csv"'
    writer = csv.writer(response)
    writer.writerow(
        ["created_at", "scan_type", "verdict", "confidence", "input_length", "indicators", "summary"]
    )
    for record in ScanRecord.objects.all():
        indicators = "; ".join(record.indicators or [])
        writer.writerow(
            [
                record.created_at.isoformat(),
                record.scan_type,
                record.verdict,
                record.confidence if record.confidence is not None else "",
                record.input_length,
                indicators,
                record.summary,
            ]
        )
    return response
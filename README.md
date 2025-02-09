# medical-fraud-dementia
finding fraud in hospice, medicare specifially for dementia patients in a adult foster home setting
import os
import re
import pytesseract
import pandas as pd
from pdfminer.high_level import extract_text
from docx import Document
from PIL import Image

# Path to discovery folder (Windows D: drive is mounted as /mnt/d/)
directory = "/mnt/d/00000000000/Bing/00 All discovery"

# Known dangerous drug interactions (Expand as needed)
dangerous_combinations = [
    (r"opioid", r"benzodiazepine"),  # High risk of overdose
    (r"antipsychotic", r"dementia"),  # Increased mortality risk
    (r"warfarin", r"NSAID"),  # High bleeding risk
    (r"stimulant", r"antidepressant"),  # Can trigger heart issues
]

# Known fraudulent practices
fraud_patterns = [
    (r"ghost patient", "🚨 Possible ghost billing (billing for non-existent patients)."),
    (r"kickback|bribe|incentive", "🚨 Potential illegal medical kickback scheme."),
    (r"false claims act|fraudulent billing", "🚨 Billing fraud detected."),
    (r"medically unnecessary", "⚠️ Possible unnecessary treatment to increase billing."),
    (r"upcoding", "⚠️ Service billed at a higher level than provided."),
    (r"double billing|duplicate billing", "⚠️ Patient charged twice for same service."),
]

# Function to extract text from PDFs
def extract_pdf_text(pdf_path):
    try:
        return extract_text(pdf_path)
    except Exception as e:
        return f"Error extracting text from {pdf_path}: {e}"

# Function to extract text from DOCX files
def extract_docx_text(docx_path):
    try:
        doc = Document(docx_path)
        return "\n".join([p.text for p in doc.paragraphs])
    except Exception as e:
        return f"Error extracting text from {docx_path}: {e}"

# Function to extract text from images using OCR
def extract_image_text(image_path):
    try:
        return pytesseract.image_to_string(Image.open(image_path))
    except Exception as e:
        return f"Error extracting text from {image_path}: {e}"

# Function to detect fraud patterns
def detect_fraud(text, filename):
    red_flags = []

    ### 🚨 DEMENTIA & HOSPICE FRAUD DETECTION ###
    
    # FAST 7A diagnosis but no supporting symptoms
    if re.search(r"FAST 7A", text, re.IGNORECASE):
        if not re.search(r"(incontinence|non-ambulatory|limited speech|severe cognitive decline)", text, re.IGNORECASE):
            red_flags.append("🚨 FAST 7A Diagnosis but NO supporting medical qualifiers found.")

    # Hospice admission but patient still cognitively aware
    if re.search(r"(hospice|palliative care)", text, re.IGNORECASE):
        if re.search(r"(alert and oriented|coherent|aware|responds appropriately)", text, re.IGNORECASE):
            red_flags.append("⚠️ Hospice admitted patient despite cognitive awareness.")

    # Contradictions in condition vs. hospice eligibility
    if re.search(r"(terminal diagnosis)", text, re.IGNORECASE):
        if re.search(r"(stable condition|no decline|improving|recovered)", text, re.IGNORECASE):
            red_flags.append("⚠️ Terminal diagnosis contradicts patient status.")

    # Physician certifications missing
    if re.search(r"(hospice recertification|physician certification)", text, re.IGNORECASE):
        if not re.search(r"(face-to-face evaluation|physician saw patient|documented examination)", text, re.IGNORECASE):
            red_flags.append("🚨 Hospice certification found but NO face-to-face evaluation.")

    # Unjustified discharge/re-admission cycling
    if re.search(r"(discharged from hospice)", text, re.IGNORECASE):
        if re.search(r"(re-admitted within.*weeks)", text, re.IGNORECASE):
            red_flags.append("⚠️ Possible hospice cycling detected.")

    # Medicare billing for hospice services without qualifying conditions
    if re.search(r"(Medicare billing|insurance claim)", text, re.IGNORECASE):
        if not re.search(r"(documented pain|progressive weight loss|severe decline)", text, re.IGNORECASE):
            red_flags.append("🚨 Medicare billing found but NO qualifying conditions documented.")

    ### 🚨 MEDICATION FRAUD DETECTION ###
    
    # Dangerous medication interactions
    for drug1, drug2 in dangerous_combinations:
        if re.search(drug1, text, re.IGNORECASE) and re.search(drug2, text, re.IGNORECASE):
            red_flags.append(f"🚨 Dangerous medication interaction: {drug1} + {drug2}.")

    # Unnecessary medications for condition
    if re.search(r"(unnecessary medication|medically unjustified)", text, re.IGNORECASE):
        red_flags.append("⚠️ Possible unnecessary medication prescribed.")

    # Medications used for inappropriate purposes
    if re.search(r"(antipsychotic for dementia|opioid for mild pain)", text, re.IGNORECASE):
        red_flags.append("⚠️ Medication prescribed inappropriately for condition.")

    ### 🚨 KNOWN MEDICAL FRAUD SCHEMES ###
    
    for pattern, description in fraud_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            red_flags.append(description)

    if red_flags:
        return {"Filename": filename, "Issues": "; ".join(red_flags)}
    return None

# Store fraud results
fraud_results = []
scanned_files = []

# Iterate through all files and subfolders
for root, _, files in os.walk(directory):
    for file in files:
        file_path = os.path.join(root, file)
        text = ""

        # Print progress
        print(f"🔍 Scanning: {file_path}")

        # Extract text from supported file types
        if file.lower().endswith(".pdf"):
            text = extract_pdf_text(file_path)
        elif file.lower().endswith(".docx"):
            text = extract_docx_text(file_path)
        elif file.lower().endswith((".png", ".jpg", ".jpeg")):
            text = extract_image_text(file_path)
        else:
            print(f"⏩ Skipping unsupported file: {file_path}")
            continue  # Skip unsupported files

        # Run fraud detection
        result = detect_fraud(text, file_path)
        if result:
            fraud_results.append(result)

        # Log all scanned files
        scanned_files.append({"Filename": file_path, "Scanned": "Yes"})

# Save flagged results to a CSV report
df_scanned = pd.DataFrame(scanned_files)
df_scanned.to_csv("scanned_files.csv", index=False)

if fraud_results:
    df_fraud = pd.DataFrame(fraud_results)
    df_fraud.to_csv("fraud_report.csv", index=False)
    print("🚨 Fraud analysis complete! Results saved in fraud_report.csv.")
else:
    print("✅ No fraud indicators detected in scanned documents.")

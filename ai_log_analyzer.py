from transformers import pipeline

log_classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

def classify_log(log_text):
    result = log_classifier(log_text)[0]
    return result["label"], result["score"]

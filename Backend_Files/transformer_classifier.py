from transformers import pipeline

_transformer = None


def load_transformer():

    global _transformer

    if _transformer is None:

        _transformer = pipeline(
            "sentiment-analysis",
            model="distilbert-base-uncased-finetuned-sst-2-english"
        )

    return _transformer


def predict_transformer(text):

    model = load_transformer()

    result = model(text[:512])[0]

    score = float(result["score"])

    if result["label"] == "NEGATIVE":
        phishing_probability = score
    else:
        phishing_probability = 1 - score

    return phishing_probability
# ============================================================
# xai_engine.py
# Explainable AI helpers for phishing detection
# ============================================================

import shap
import numpy as np
import scipy.sparse as sp


def explain_keywords(subject, body, phishing_keywords):

    text = (subject + " " + body).lower()

    matched_keywords = []

    for keyword in phishing_keywords:
        if keyword.lower() in text:
            matched_keywords.append(keyword)

    return {
        "matched_keywords": matched_keywords,
        "keyword_count": len(matched_keywords)
    }


def explain_url_risk(url_features):

    risks = []

    if url_features.get("IpAddress", 0):
        risks.append(
            "URL uses raw IP address"
        )

    if url_features.get("NoHttps", 0):
        risks.append(
            "URL does not use HTTPS"
        )

    if url_features.get("EmbeddedBrandName", 0):
        risks.append(
            "Brand name embedded in URL"
        )

    if url_features.get("NumSensitiveWords", 0) > 0:
        risks.append(
            "Contains phishing-related words"
        )

    if url_features.get("RandomString", 0):
        risks.append(
            "Domain appears randomly generated"
        )

    return risks


def build_confidence_breakdown(
    email_prob,
    url_prob,
    combined_prob
):

    return {
        "email_score": round(email_prob, 4),
        "url_score": round(url_prob, 4),
        "combined_score": round(combined_prob, 4)
    }


def explain_model_features(
    model,
    tfidf_vectorizer=None,
    top_n=10
):

    try:

        feature_names = model.feature_name()

        importances = model.feature_importance(
            importance_type="gain"
        )

        feature_data = []

        tfidf_features = None

        if tfidf_vectorizer is not None:
            tfidf_features = (
                tfidf_vectorizer
                .get_feature_names_out()
            )

        for name, importance in zip(
            feature_names,
            importances
        ):

            readable_name = name

            try:

                if (
                    tfidf_features is not None
                    and name.startswith(
                        "Column_"
                    )
                ):

                    idx = int(
                        name.replace(
                            "Column_",
                            ""
                        )
                    )

                    if idx < len(
                        tfidf_features
                    ):
                        readable_name = (
                            tfidf_features[idx]
                        )

            except Exception:
                pass

            feature_data.append({
                "feature":
                    readable_name,
                "importance":
                    float(importance)
            })

        feature_data = sorted(
            feature_data,
            key=lambda x:
                x["importance"],
            reverse=True
        )

        return {
            "top_features":
                feature_data[:top_n]
        }

    except Exception as e:

        return {
            "error": str(e)
        }


def generate_shap_explanation(
    model,
    feature_vector,
    feature_names,
    top_n=10
):

    try:

        if sp.issparse(
            feature_vector
        ):
            feature_vector = (
                feature_vector
                .toarray()
            )

        explainer = (
            shap.TreeExplainer(
                model
            )
        )

        shap_values = (
            explainer.shap_values(
                feature_vector
            )
        )

        if isinstance(
            shap_values,
            list
        ):
            shap_values = shap_values[0]

        values = np.array(
            shap_values
        ).flatten()

        contributions = []

        for name, value in zip(
            feature_names,
            values
        ):

            contributions.append({
                "feature":
                    str(name),
                "impact":
                    float(value)
            })

        contributions = sorted(
            contributions,
            key=lambda x:
                abs(
                    x["impact"]
                ),
            reverse=True
        )

        return {
            "top_contributors":
                contributions[:top_n]
        }

    except Exception as e:

        return {
            "error": str(e)
        }
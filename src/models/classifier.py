"""
AI Deep Learning Model for Scam Detection
==========================================
LSTM + Attention based text classifier trained on scam/legitimate message patterns.
Includes:
  - Text preprocessing pipeline
  - Tokenization & sequence padding
  - LSTM model with multi-head attention
  - Model training, evaluation & persistence
  - Online learning (incremental fine-tuning)
"""

import os
import json
import pickle
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from datetime import datetime

from loguru import logger

# Graceful TensorFlow import
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, callbacks
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logger.warning("TensorFlow not available — using rule-based fallback only.")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, roc_auc_score
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# ─────────────────────────────────────────────────────────────
# Text Preprocessor
# ─────────────────────────────────────────────────────────────

class TextPreprocessor:
    """Cleans and normalizes text for model input."""

    import re as _re

    CONTRACTIONS = {
        "don't": "do not", "won't": "will not", "can't": "cannot",
        "i'm": "i am", "you're": "you are", "it's": "it is",
        "we'll": "we will", "they're": "they are", "i've": "i have",
    }

    def preprocess(self, text: str) -> str:
        import re
        text = text.lower()
        # Expand contractions
        for c, expanded in self.CONTRACTIONS.items():
            text = text.replace(c, expanded)
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        # Remove non-printable characters
        text = re.sub(r'[^\x20-\x7E]', ' ', text)
        return text.strip()


# ─────────────────────────────────────────────────────────────
# LSTM + Attention Model
# ─────────────────────────────────────────────────────────────

class LSTMScamClassifier:
    """
    Deep LSTM model with self-attention for scam text classification.
    
    Architecture:
        Embedding → BiLSTM → Multi-Head Attention → Dense → Output
    """

    DEFAULT_VOCAB_SIZE   = 20_000
    DEFAULT_MAX_LENGTH   = 256
    DEFAULT_EMBED_DIM    = 128
    DEFAULT_LSTM_UNITS   = 128
    DEFAULT_ATTENTION_HEADS = 4
    DEFAULT_DROPOUT      = 0.3

    def __init__(self, model_dir: str = "./data/models"):
        self.model_dir    = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.preprocessor = TextPreprocessor()
        self.tokenizer    = None
        self.model        = None
        self.is_trained   = False

        self._load_if_exists()

    def _build_model(self) -> "tf.keras.Model":
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow is required for the LSTM model.")

        vocab_size = self.DEFAULT_VOCAB_SIZE
        max_len    = self.DEFAULT_MAX_LENGTH
        embed_dim  = self.DEFAULT_EMBED_DIM
        lstm_units = self.DEFAULT_LSTM_UNITS
        heads      = self.DEFAULT_ATTENTION_HEADS
        dropout    = self.DEFAULT_DROPOUT

        # ── Input ─────────────────────────────────────────────
        inputs = layers.Input(shape=(max_len,), name="token_ids")

        # ── Embedding ─────────────────────────────────────────
        x = layers.Embedding(vocab_size + 1, embed_dim,
                              input_length=max_len, name="embedding")(inputs)
        x = layers.SpatialDropout1D(dropout)(x)

        # ── Bidirectional LSTM ────────────────────────────────
        x = layers.Bidirectional(
            layers.LSTM(lstm_units, return_sequences=True, dropout=dropout),
            name="bi_lstm"
        )(x)

        # ── Multi-Head Self-Attention ─────────────────────────
        attn_out = layers.MultiHeadAttention(
            num_heads=heads, key_dim=lstm_units // heads, name="mha"
        )(x, x)
        x = layers.Add()([x, attn_out])
        x = layers.LayerNormalization()(x)

        # ── Pooling ───────────────────────────────────────────
        x = layers.GlobalAveragePooling1D(name="gap")(x)

        # ── Classification Head ───────────────────────────────
        x = layers.Dense(128, activation="relu", name="dense_1")(x)
        x = layers.Dropout(dropout)(x)
        x = layers.Dense(64, activation="relu", name="dense_2")(x)
        x = layers.Dropout(dropout / 2)(x)
        outputs = layers.Dense(1, activation="sigmoid", name="output")(x)

        model = models.Model(inputs=inputs, outputs=outputs, name="LSTMScamClassifier")
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
            loss="binary_crossentropy",
            metrics=["accuracy", tf.keras.metrics.AUC(name="auc")]
        )

        return model

    def train(self, texts: List[str], labels: List[int],
              epochs: int = 20, batch_size: int = 32,
              validation_split: float = 0.15) -> Dict:
        """Train the LSTM model on labeled examples."""
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow required for training.")

        logger.info(f"Training LSTM model on {len(texts)} samples...")

        # Preprocess
        cleaned = [self.preprocessor.preprocess(t) for t in texts]

        # Tokenize
        self.tokenizer = Tokenizer(num_words=self.DEFAULT_VOCAB_SIZE, oov_token="<OOV>")
        self.tokenizer.fit_on_texts(cleaned)
        sequences = self.tokenizer.texts_to_sequences(cleaned)
        X = pad_sequences(sequences, maxlen=self.DEFAULT_MAX_LENGTH, padding="post", truncating="post")
        y = np.array(labels)

        # Build & train
        self.model = self._build_model()

        cb_list = [
            callbacks.EarlyStopping(patience=5, restore_best_weights=True, monitor="val_auc"),
            callbacks.ReduceLROnPlateau(factor=0.5, patience=3, monitor="val_loss"),
            callbacks.ModelCheckpoint(
                str(self.model_dir / "best_lstm.keras"),
                save_best_only=True, monitor="val_auc"
            )
        ]

        history = self.model.fit(
            X, y,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            callbacks=cb_list,
            verbose=1
        )

        self.is_trained = True
        self._save()

        # Return training summary
        return {
            "final_accuracy":   float(history.history["accuracy"][-1]),
            "final_val_accuracy": float(history.history.get("val_accuracy", [0])[-1]),
            "final_auc":        float(history.history.get("auc", [0])[-1]),
            "epochs_trained":   len(history.history["loss"]),
        }

    def predict(self, text: str) -> float:
        """Return scam probability [0.0, 1.0]."""
        if not self.is_trained or not TF_AVAILABLE:
            return 0.5  # Neutral fallback

        cleaned   = self.preprocessor.preprocess(text)
        sequence  = self.tokenizer.texts_to_sequences([cleaned])
        padded    = pad_sequences(sequence, maxlen=self.DEFAULT_MAX_LENGTH,
                                  padding="post", truncating="post")
        prob      = float(self.model.predict(padded, verbose=0)[0][0])
        return prob

    def _save(self):
        try:
            if self.model:
                self.model.save(str(self.model_dir / "lstm_model.keras"))
            if self.tokenizer:
                with open(self.model_dir / "tokenizer.pkl", "wb") as f:
                    pickle.dump(self.tokenizer, f)
            logger.info(f"Model saved to {self.model_dir}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _load_if_exists(self):
        model_path     = self.model_dir / "lstm_model.keras"
        tokenizer_path = self.model_dir / "tokenizer.pkl"

        if model_path.exists() and tokenizer_path.exists() and TF_AVAILABLE:
            try:
                self.model = models.load_model(str(model_path))
                with open(tokenizer_path, "rb") as f:
                    self.tokenizer = pickle.load(f)
                self.is_trained = True
                logger.info("Pre-trained LSTM model loaded.")
            except Exception as e:
                logger.warning(f"Could not load saved model: {e}")


# ─────────────────────────────────────────────────────────────
# Gradient Boosting Fallback (sklearn)
# ─────────────────────────────────────────────────────────────

class GBScamClassifier:
    """
    Gradient Boosting classifier on TF-IDF features.
    Serves as a fast, lightweight alternative/complement to the LSTM model.
    """

    def __init__(self, model_dir: str = "./data/models"):
        self.model_dir  = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.vectorizer = None
        self.clf        = None
        self.is_trained = False
        self._load_if_exists()

    def train(self, texts: List[str], labels: List[int]) -> Dict:
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn required for GBScamClassifier.")

        logger.info(f"Training Gradient Boosting on {len(texts)} samples...")

        self.vectorizer = TfidfVectorizer(
            max_features=10_000, ngram_range=(1, 3),
            sublinear_tf=True, min_df=2
        )
        X = self.vectorizer.fit_transform(texts)
        y = np.array(labels)

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )

        self.clf = GradientBoostingClassifier(
            n_estimators=200, learning_rate=0.1,
            max_depth=5, random_state=42
        )
        self.clf.fit(X_train, y_train)

        y_pred = self.clf.predict(X_val)
        y_prob = self.clf.predict_proba(X_val)[:, 1]

        report = classification_report(y_val, y_pred, output_dict=True)
        auc    = roc_auc_score(y_val, y_prob)

        self.is_trained = True
        self._save()

        return {
            "accuracy":  report.get("accuracy", 0.0),
            "roc_auc":   float(auc),
            "precision": report.get("1", {}).get("precision", 0.0),
            "recall":    report.get("1", {}).get("recall", 0.0),
        }

    def predict(self, text: str) -> float:
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return 0.5

        X = self.vectorizer.transform([text])
        prob = float(self.clf.predict_proba(X)[0][1])
        return prob

    def _save(self):
        try:
            joblib.dump(self.vectorizer, self.model_dir / "tfidf_vectorizer.pkl")
            joblib.dump(self.clf, self.model_dir / "gb_classifier.pkl")
            logger.info("GB model saved.")
        except Exception as e:
            logger.error(f"Failed to save GB model: {e}")

    def _load_if_exists(self):
        vec_path = self.model_dir / "tfidf_vectorizer.pkl"
        clf_path = self.model_dir / "gb_classifier.pkl"

        if vec_path.exists() and clf_path.exists() and SKLEARN_AVAILABLE:
            try:
                self.vectorizer = joblib.load(vec_path)
                self.clf        = joblib.load(clf_path)
                self.is_trained = True
                logger.info("Pre-trained GB classifier loaded.")
            except Exception as e:
                logger.warning(f"Could not load GB model: {e}")


# ─────────────────────────────────────────────────────────────
# Model Manager (unified interface)
# ─────────────────────────────────────────────────────────────

class ModelManager:
    """
    Unified interface combining LSTM and GB classifiers.
    Returns the ensemble ML probability score.
    """

    def __init__(self, model_dir: str = "./data/models"):
        self.lstm = LSTMScamClassifier(model_dir)
        self.gb   = GBScamClassifier(model_dir)

    @property
    def has_trained_models(self) -> bool:
        return self.lstm.is_trained or self.gb.is_trained

    def predict(self, text: str) -> float:
        """Ensemble ML prediction. Returns scam probability."""
        lstm_prob = self.lstm.predict(text) if self.lstm.is_trained else None
        gb_prob   = self.gb.predict(text)   if self.gb.is_trained   else None

        if lstm_prob is not None and gb_prob is not None:
            return 0.6 * lstm_prob + 0.4 * gb_prob
        elif lstm_prob is not None:
            return lstm_prob
        elif gb_prob is not None:
            return gb_prob
        return 0.5  # No trained models yet

    def train(self, texts: List[str], labels: List[int]) -> Dict:
        """Train both models."""
        results = {}

        if SKLEARN_AVAILABLE:
            results["gradient_boosting"] = self.gb.train(texts, labels)

        if TF_AVAILABLE:
            results["lstm"] = self.lstm.train(texts, labels)

        return results

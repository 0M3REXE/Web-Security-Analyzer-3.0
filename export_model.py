"""
export_model.py – Train the TF/Keras security model and export it to ONNX.

Usage:
    pip install tensorflow tf2onnx scikit-learn numpy
    python export_model.py

Outputs:
    web_security_analyzer/model.onnx  – ONNX model for the Rust runtime
    web_security_analyzer/scaler.json – StandardScaler parameters (mean + std)
"""

import os
import json
import random
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import tensorflow as tf
import tf2onnx
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


# ---------------------------------------------------------------------------
# Synthetic dataset (same logic as the original code)
# ---------------------------------------------------------------------------

def generate_synthetic_dataset(n_samples: int = 10000):
    """Generate synthetic security dataset.

    Features (9 total):
        uses_https, suspicious_patterns_count, domain_age_days,
        uses_suspicious_tld, domain_length, uses_ip,
        redirects, subdomains_count, url_length
    """
    X, y = [], []
    for _ in range(n_samples):
        is_malicious = random.randint(0, 1)

        uses_https = (
            random.choice([0, 1])
            if is_malicious
            else random.choice([0, 1, 1, 1, 1])
        )

        if is_malicious:
            suspicious_patterns_count = random.choices(
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                weights=[1, 5, 10, 15, 20, 25, 15, 10, 5, 3, 1],
            )[0]
        else:
            suspicious_patterns_count = random.choices(
                [0, 1, 2, 3, 4, 5], weights=[60, 30, 7, 2, 1, 0.5]
            )[0]

        if is_malicious:
            domain_age_days = random.choices(
                range(1, 180), weights=[i * 0.9 for i in range(179, 0, -1)]
            )[0]
        else:
            domain_age_days = random.choices(
                range(30, 10000), weights=[1 for _ in range(9970)]
            )[0]

        uses_suspicious_tld = (
            random.choice([0, 1]) if is_malicious else random.choice([0, 0, 0, 1])
        )

        domain_length = (
            random.randint(10, 50) if is_malicious else random.randint(3, 25)
        )

        uses_ip = (
            random.choice([0, 1]) if is_malicious else random.choice([0, 0, 0, 1])
        )

        if is_malicious:
            redirects = random.choices(
                range(0, 10), weights=[30, 20, 15, 10, 8, 5, 4, 3, 3, 2]
            )[0]
        else:
            redirects = random.choices(
                range(0, 5), weights=[50, 30, 15, 4, 1]
            )[0]

        subdomains_count = (
            random.randint(0, 5) if is_malicious else random.randint(0, 2)
        )
        url_length = (
            random.randint(50, 200) if is_malicious else random.randint(10, 80)
        )

        X.append(
            [
                uses_https,
                suspicious_patterns_count,
                domain_age_days,
                uses_suspicious_tld,
                domain_length,
                uses_ip,
                redirects,
                subdomains_count,
                url_length,
            ]
        )
        y.append(is_malicious)

    return np.array(X, dtype="float32"), np.array(y, dtype="float32")


# ---------------------------------------------------------------------------
# Model definition (mirrors security_analyzer_3.py)
# ---------------------------------------------------------------------------

def build_model() -> tf.keras.Model:
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Dense(64, activation="relu", input_shape=(9,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(16, activation="relu"),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train(n_samples: int = 10000):
    print(f"Generating {n_samples} synthetic training samples …")
    X, y = generate_synthetic_dataset(n_samples)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)

    model = build_model()

    early_stop = tf.keras.callbacks.EarlyStopping(
        monitor="val_loss", patience=10, restore_best_weights=True
    )
    print("Training …")
    history = model.fit(
        X_train_s,
        y_train,
        epochs=100,
        batch_size=32,
        validation_data=(X_val_s, y_val),
        callbacks=[early_stop],
        verbose=1,
    )

    val_acc = max(history.history["val_accuracy"])
    print(f"Best validation accuracy: {val_acc:.4f}")

    return model, scaler


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export(model: tf.keras.Model, scaler: StandardScaler, out_dir: str = "web_security_analyzer"):
    os.makedirs(out_dir, exist_ok=True)

    # -- ONNX --
    onnx_path = os.path.join(out_dir, "model.onnx")
    input_signature = [
        tf.TensorSpec(shape=(None, 9), dtype=tf.float32, name="input")
    ]
    model_proto, _ = tf2onnx.convert.from_keras(
        model, input_signature=input_signature, opset=13
    )
    with open(onnx_path, "wb") as f:
        f.write(model_proto.SerializeToString())
    print(f"ONNX model saved → {onnx_path}")

    # -- Scaler parameters (JSON so Rust can load them without scikit-learn) --
    scaler_path = os.path.join(out_dir, "scaler.json")
    scaler_data = {
        "mean": scaler.mean_.tolist(),
        "std": scaler.scale_.tolist(),
    }
    with open(scaler_path, "w") as f:
        json.dump(scaler_data, f, indent=2)
    print(f"Scaler parameters saved → {scaler_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    model, scaler = train()
    export(model, scaler)
    print("\nDone! You can now run the Rust analyzer:")
    print("  cd web_security_analyzer && cargo run -- --url https://example.com")

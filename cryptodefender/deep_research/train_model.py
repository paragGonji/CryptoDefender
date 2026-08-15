import os
import json
import warnings

import joblib
import numpy as np
import pandas as pd

import torch
import torch.nn as nn

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix
)

from hybrid_model import HybridMiningDetector


warnings.filterwarnings("ignore")


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATASET_DIR = os.path.join(
    BASE_DIR,
    "dataset"
)

NORMAL_FILE = os.path.join(
    DATASET_DIR,
    "final-normal-data-set.csv"
)

ANORMAL_FILE = os.path.join(
    DATASET_DIR,
    "final-anormal-data-set.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "model"
)

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


MODEL_PATH = os.path.join(
    MODEL_DIR,
    "hybrid_mining_detector.pt"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "scaler.pkl"
)

METADATA_PATH = os.path.join(
    MODEL_DIR,
    "metadata.json"
)


# ============================================================
# FEATURES
# ============================================================

FEATURES = [
    "cpu",
    "memory",
    "threads",
    "process_age",
    "known_miner",
    "suspicious_path",
    "unknown_exe"
]


# ============================================================
# COLUMN ALIASES
# ============================================================

COLUMN_ALIASES = {

    "cpu": [
        "cpu",
        "cpu_usage",
        "cpu_percent",
        "cpu_percentage",
        "cpu usage",
        "cpu usage (%)",
        "cpu (%)",
        "processor",
        "processor_usage",
        "processor usage"
    ],

    "memory": [
        "memory",
        "memory_usage",
        "memory_percent",
        "memory_percentage",
        "memory usage",
        "memory usage (%)",
        "mem",
        "ram",
        "working_set",
        "working set",
        "private_bytes",
        "private bytes"
    ],

    "threads": [
        "threads",
        "thread",
        "num_threads",
        "number_of_threads",
        "number of threads",
        "thread_count",
        "thread count"
    ],

    "process_age": [
        "process_age",
        "process age",
        "age",
        "process_lifetime",
        "process lifetime",
        "lifetime",
        "duration",
        "uptime"
    ],

    "name": [
        "name",
        "process_name",
        "process name",
        "process",
        "processname",
        "exe",
        "executable",
        "executable_name",
        "executable name",
        "filename",
        "file_name"
    ],

    "path": [
        "path",
        "exe_path",
        "exe path",
        "executable_path",
        "executable path",
        "process_path",
        "process path",
        "filepath",
        "file_path"
    ]
}


# ============================================================
# NORMALIZE COLUMN NAME
# ============================================================

def normalize_column_name(name):

    return (
        str(name)
        .strip()
        .lower()
        .replace("-", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace("(", "")
        .replace(")", "")
        .replace("%", "percent")
        .replace(" ", "_")
    )


# ============================================================
# FIND COLUMN
# ============================================================

def find_column(df, aliases):

    normalized = {}

    for column in df.columns:

        normalized[
            normalize_column_name(column)
        ] = column

    for alias in aliases:

        key = normalize_column_name(
            alias
        )

        if key in normalized:

            return normalized[key]

    # partial matching
    for column in df.columns:

        normalized_column = normalize_column_name(
            column
        )

        for alias in aliases:

            normalized_alias = normalize_column_name(
                alias
            )

            if (
                normalized_alias
                in normalized_column
            ):

                return column

    return None


# ============================================================
# NUMERIC CONVERSION
# ============================================================

def numeric_series(series):

    if series is None:

        return None

    if pd.api.types.is_numeric_dtype(
        series
    ):

        return pd.to_numeric(
            series,
            errors="coerce"
        )

    cleaned = (
        series
        .astype(str)
        .str.replace(
            "%",
            "",
            regex=False
        )
        .str.replace(
            ",",
            "",
            regex=False
        )
        .str.strip()
    )

    return pd.to_numeric(
        cleaned,
        errors="coerce"
    )


# ============================================================
# LOAD CSV
# ============================================================

def load_csv(path, label_name):

    print()
    print(
        "Loading:",
        os.path.basename(path)
    )

    df = pd.read_csv(
        path,
        low_memory=False
    )

    print(
        "Rows:",
        len(df)
    )

    print()
    print("CSV columns:")

    for column in df.columns:

        print(
            "  -",
            column
        )

    print()

    return df


# ============================================================
# BUILD FEATURES
# ============================================================

def build_features(
    df,
    label
):

    print()
    print(
        "Processing dataset:",
        label
    )

    print(
        "Rows:",
        len(df)
    )

    # --------------------------------------------------------
    # FIND SOURCE COLUMNS
    # --------------------------------------------------------

    cpu_column = find_column(
        df,
        COLUMN_ALIASES["cpu"]
    )

    memory_column = find_column(
        df,
        COLUMN_ALIASES["memory"]
    )

    threads_column = find_column(
        df,
        COLUMN_ALIASES["threads"]
    )

    age_column = find_column(
        df,
        COLUMN_ALIASES["process_age"]
    )

    name_column = find_column(
        df,
        COLUMN_ALIASES["name"]
    )

    path_column = find_column(
        df,
        COLUMN_ALIASES["path"]
    )


    print(
        "Matched columns:"
    )

    print(
        "  CPU:",
        cpu_column
    )

    print(
        "  Memory:",
        memory_column
    )

    print(
        "  Threads:",
        threads_column
    )

    print(
        "  Process age:",
        age_column
    )

    print(
        "  Process name:",
        name_column
    )

    print(
        "  Executable path:",
        path_column
    )


    # --------------------------------------------------------
    # REQUIRED NUMERIC FEATURES
    # --------------------------------------------------------

    if cpu_column is None:

        raise ValueError(
            "CPU column was not found in the dataset."
        )

    if memory_column is None:

        raise ValueError(
            "Memory column was not found in the dataset."
        )

    if threads_column is None:

        raise ValueError(
            "Threads column was not found in the dataset."
        )


    cpu = numeric_series(
        df[cpu_column]
    )

    memory = numeric_series(
        df[memory_column]
    )

    threads = numeric_series(
        df[threads_column]
    )


    # --------------------------------------------------------
    # OPTIONAL PROCESS AGE
    # --------------------------------------------------------

    if age_column is not None:

        process_age = numeric_series(
            df[age_column]
        )

    else:

        process_age = pd.Series(
            np.zeros(len(df)),
            index=df.index
        )


    # --------------------------------------------------------
    # PROCESS NAME
    # --------------------------------------------------------

    if name_column is not None:

        names = (
            df[name_column]
            .fillna("")
            .astype(str)
            .str.lower()
        )

    else:

        names = pd.Series(
            "",
            index=df.index
        )


    # --------------------------------------------------------
    # EXECUTABLE PATH
    # --------------------------------------------------------

    if path_column is not None:

        paths = (
            df[path_column]
            .fillna("")
            .astype(str)
            .str.lower()
        )

    else:

        paths = pd.Series(
            "",
            index=df.index
        )


    # --------------------------------------------------------
    # KNOWN MINER
    # --------------------------------------------------------

    miner_names = [
        "xmrig",
        "minerd",
        "cpuminer",
        "cgminer",
        "bfgminer",
        "nanominer",
        "lolminer",
        "nbminer",
        "t-rex",
        "trex",
        "phoenixminer",
        "ethminer",
        "claymore",
        "teamredminer",
        "xmr-stak",
        "teamred"
    ]

    known_miner = np.zeros(
        len(df),
        dtype=np.float32
    )

    for miner in miner_names:

        known_miner = np.maximum(
            known_miner,
            names.str.contains(
                miner,
                regex=False,
                na=False
            ).astype(np.float32)
        )


    # --------------------------------------------------------
    # SUSPICIOUS PATH
    # --------------------------------------------------------

    suspicious_locations = [
        "\\temp\\",
        "/temp/",
        "\\appdata\\local\\temp\\",
        "/appdata/local/temp/",
        "\\downloads\\",
        "/downloads/",
        "\\public\\",
        "/public/",
        "\\programdata\\",
        "/programdata/"
    ]

    suspicious_path = np.zeros(
        len(df),
        dtype=np.float32
    )

    for location in suspicious_locations:

        suspicious_path = np.maximum(
            suspicious_path,
            paths.str.contains(
                location,
                regex=False,
                na=False
            ).astype(np.float32)
        )


    # --------------------------------------------------------
    # UNKNOWN EXECUTABLE
    # --------------------------------------------------------

    known_windows_processes = [
        "chrome.exe",
        "brave.exe",
        "firefox.exe",
        "explorer.exe",
        "svchost.exe",
        "dwm.exe",
        "python.exe",
        "pythonw.exe",
        "code.exe",
        "notepad.exe",
        "discord.exe",
        "spotify.exe",
        "system",
        "system idle process",
        "wmiprvse.exe",
        "windowsterminal.exe"
    ]

    unknown_exe = (
        names.str.endswith(
            ".exe",
            na=False
        )
        &
        ~names.isin(
            known_windows_processes
        )
    ).astype(
        np.float32
    )


    # --------------------------------------------------------
    # CREATE DATAFRAME
    # --------------------------------------------------------

    result = pd.DataFrame({

        "cpu":
            cpu,

        "memory":
            memory,

        "threads":
            threads,

        "process_age":
            process_age,

        "known_miner":
            known_miner,

        "suspicious_path":
            suspicious_path,

        "unknown_exe":
            unknown_exe,

        "label":
            label
    })


    # --------------------------------------------------------
    # CLEAN NUMERIC VALUES
    # --------------------------------------------------------

    for feature in FEATURES:

        result[feature] = pd.to_numeric(
            result[feature],
            errors="coerce"
        )


    result = result.replace(
        [np.inf, -np.inf],
        np.nan
    )

    result = result.dropna(
        subset=FEATURES
    )


    # --------------------------------------------------------
    # REMOVE IMPOSSIBLE VALUES
    # --------------------------------------------------------

    result["cpu"] = result["cpu"].clip(
        lower=0
    )

    result["memory"] = result["memory"].clip(
        lower=0
    )

    result["threads"] = result["threads"].clip(
        lower=0
    )

    result["process_age"] = result[
        "process_age"
    ].clip(
        lower=0
    )


    print()
    print(
        "Feature statistics:"
    )

    print(
        result[FEATURES].describe()
    )


    return result


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print(
        "       CRYPTO DEFENDER REAL DATASET TRAINING"
    )
    print("=" * 70)
    print()


    # ========================================================
    # LOAD DATA
    # ========================================================

    normal_df = load_csv(
        NORMAL_FILE,
        "NORMAL"
    )

    mining_df = load_csv(
        ANORMAL_FILE,
        "MINING"
    )


    # ========================================================
    # PROCESS DATA
    # ========================================================

    normal = build_features(
        normal_df,
        0
    )

    mining = build_features(
        mining_df,
        1
    )


    # ========================================================
    # COMBINE
    # ========================================================

    df = pd.concat(
        [
            normal,
            mining
        ],
        ignore_index=True
    )


    print()
    print("=" * 70)
    print(
        "DATASET SUMMARY"
    )
    print("=" * 70)

    print(
        "Total samples:",
        len(df)
    )

    print(
        "Normal samples:",
        int(
            (df["label"] == 0).sum()
        )
    )

    print(
        "Mining samples:",
        int(
            (df["label"] == 1).sum()
        )
    )


    # ========================================================
    # CHECK FEATURES
    # ========================================================

    print()
    print(
        "Final feature statistics:"
    )

    print(
        df[FEATURES].describe()
    )


    # ========================================================
    # CHECK FOR ZERO FEATURES
    # ========================================================

    print()
    print(
        "Feature variation:"
    )

    for feature in FEATURES:

        unique_count = (
            df[feature]
            .nunique()
        )

        print(
            f"{feature:20s}: "
            f"{unique_count} unique values"
        )

        if unique_count <= 1:

            print(
                f"WARNING: {feature} "
                f"has no variation."
            )


    # ========================================================
    # BALANCE DATASET
    # ========================================================

    normal_data = df[
        df["label"] == 0
    ]

    mining_data = df[
        df["label"] == 1
    ]


    # Use equal class sizes for training.
    # This prevents the model from simply predicting NORMAL.

    sample_count = min(
        len(normal_data),
        len(mining_data)
    )


    normal_data = normal_data.sample(
        n=sample_count,
        random_state=42
    )

    mining_data = mining_data.sample(
        n=sample_count,
        random_state=42
    )


    balanced_df = pd.concat(
        [
            normal_data,
            mining_data
        ],
        ignore_index=True
    ).sample(
        frac=1.0,
        random_state=42
    ).reset_index(
        drop=True
    )


    print()
    print(
        "=" * 70
    )

    print(
        "BALANCED DATASET"
    )

    print(
        "=" * 70
    )

    print(
        "Normal:",
        int(
            (balanced_df["label"] == 0).sum()
        )
    )

    print(
        "Mining:",
        int(
            (balanced_df["label"] == 1).sum()
        )
    )


    # ========================================================
    # X / Y
    # ========================================================

    X = balanced_df[
        FEATURES
    ].values.astype(
        np.float32
    )

    y = balanced_df[
        "label"
    ].values.astype(
        np.int64
    )


    # ========================================================
    # TRAIN / TEST SPLIT
    # ========================================================

    X_train, X_test, y_train, y_test = train_test_split(

        X,
        y,

        test_size=0.20,

        random_state=42,

        stratify=y
    )


    print()
    print(
        "Training samples:",
        len(X_train)
    )

    print(
        "Testing samples:",
        len(X_test)
    )


    # ========================================================
    # SCALER
    # ========================================================

    scaler = StandardScaler()

    X_train = scaler.fit_transform(
        X_train
    )

    X_test = scaler.transform(
        X_test
    )


    # ========================================================
    # SEQUENCE FORMAT
    # ========================================================

    X_train = X_train.reshape(
        X_train.shape[0],
        1,
        X_train.shape[1]
    )

    X_test = X_test.reshape(
        X_test.shape[0],
        1,
        X_test.shape[1]
    )


    # ========================================================
    # DEVICE
    # ========================================================

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print()
    print(
        "Device:",
        device
    )


    # ========================================================
    # MODEL
    # ========================================================

    model = HybridMiningDetector(
        input_size=len(FEATURES),
        hidden_size=64
    ).to(device)


    # ========================================================
    # TENSORS
    # ========================================================

    X_train_tensor = torch.tensor(
        X_train,
        dtype=torch.float32
    ).to(device)

    y_train_tensor = torch.tensor(
        y_train,
        dtype=torch.long
    ).to(device)


    X_test_tensor = torch.tensor(
        X_test,
        dtype=torch.float32
    ).to(device)


    # ========================================================
    # OPTIMIZER
    # ========================================================

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=0.0005,
        weight_decay=1e-4
    )


    # ========================================================
    # CLASSIFICATION LOSS
    # ========================================================

    criterion = nn.CrossEntropyLoss()


    # ========================================================
    # TRAINING
    # ========================================================

    EPOCHS = 100

    print()
    print("=" * 70)
    print(
        "TRAINING HYBRID CNN + LSTM + AUTOENCODER"
    )
    print("=" * 70)


    best_accuracy = 0.0

    best_state = None


    for epoch in range(EPOCHS):

        model.train()

        optimizer.zero_grad()


        logits, reconstructed = model(
            X_train_tensor
        )


        classification_loss = criterion(
            logits,
            y_train_tensor
        )


        last_features = (
            X_train_tensor[:, -1, :]
        )


        reconstruction_loss = (
            nn.functional.mse_loss(
                reconstructed,
                last_features
            )
        )


        loss = (
            classification_loss
            +
            0.05 * reconstruction_loss
        )


        loss.backward()


        torch.nn.utils.clip_grad_norm_(
            model.parameters(),
            max_norm=1.0
        )


        optimizer.step()


        # ====================================================
        # VALIDATION
        # ====================================================

        model.eval()

        with torch.no_grad():

            validation_logits, _ = model(
                X_test_tensor
            )

            validation_predictions = (
                torch.argmax(
                    validation_logits,
                    dim=1
                )
                .cpu()
                .numpy()
            )


        accuracy = accuracy_score(
            y_test,
            validation_predictions
        )


        if accuracy > best_accuracy:

            best_accuracy = accuracy

            best_state = {
                key: value.detach().cpu().clone()
                for key, value
                in model.state_dict().items()
            }


        if (
            epoch % 5 == 0
            or epoch == EPOCHS - 1
        ):

            print(
                f"Epoch {epoch:03d}/{EPOCHS} | "
                f"Classification: "
                f"{classification_loss.item():.4f} | "
                f"Reconstruction: "
                f"{reconstruction_loss.item():.4f} | "
                f"Total: "
                f"{loss.item():.4f} | "
                f"Validation Accuracy: "
                f"{accuracy * 100:.2f}%"
            )


    # ========================================================
    # RESTORE BEST MODEL
    # ========================================================

    if best_state is not None:

        model.load_state_dict(
            best_state
        )


    # ========================================================
    # FINAL EVALUATION
    # ========================================================

    print()
    print("=" * 70)
    print(
        "FINAL MODEL EVALUATION"
    )
    print("=" * 70)


    model.eval()


    with torch.no_grad():

        logits, reconstructed = model(
            X_test_tensor
        )

        probabilities = torch.softmax(
            logits,
            dim=1
        )

        predictions = torch.argmax(
            probabilities,
            dim=1
        ).cpu().numpy()


    accuracy = accuracy_score(
        y_test,
        predictions
    )


    print()
    print(
        f"MODEL ACCURACY: "
        f"{accuracy * 100:.2f}%"
    )


    print()
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "NORMAL",
                "MINING"
            ],
            digits=4,
            zero_division=0
        )
    )


    print()
    print(
        "CONFUSION MATRIX"
    )

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )


    # ========================================================
    # SAVE MODEL
    # ========================================================

    torch.save(
        {
            "model_state_dict":
                model.state_dict(),

            "features":
                FEATURES,

            "accuracy":
                float(accuracy),

            "best_accuracy":
                float(best_accuracy),

            "epochs":
                EPOCHS,

            "version":
                "2.0-real-dataset"
        },
        MODEL_PATH
    )


    # ========================================================
    # SAVE SCALER
    # ========================================================

    joblib.dump(
        scaler,
        SCALER_PATH
    )


    # ========================================================
    # SAVE METADATA
    # ========================================================

    metadata = {

        "features":
            FEATURES,

        "version":
            "2.0-real-dataset",

        "accuracy":
            float(accuracy),

        "accuracy_percent":
            float(
                accuracy * 100
            ),

        "best_accuracy":
            float(best_accuracy),

        "training_samples":
            int(len(X_train)),

        "testing_samples":
            int(len(X_test)),

        "normal_samples":
            int(
                (balanced_df["label"] == 0).sum()
            ),

        "mining_samples":
            int(
                (balanced_df["label"] == 1).sum()
            ),

        "epochs":
            EPOCHS
    }


    with open(
        METADATA_PATH,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metadata,
            f,
            indent=4
        )


    # ========================================================
    # COMPLETE
    # ========================================================

    print()
    print("=" * 70)
    print(
        "MODEL TRAINING COMPLETE"
    )
    print("=" * 70)

    print()

    print(
        "Model:"
    )

    print(
        MODEL_PATH
    )

    print()

    print(
        "Scaler:"
    )

    print(
        SCALER_PATH
    )

    print()

    print(
        "Metadata:"
    )

    print(
        METADATA_PATH
    )

    print()

    print(
        f"Final accuracy: "
        f"{accuracy * 100:.2f}%"
    )

    print(
        f"Best validation accuracy: "
        f"{best_accuracy * 100:.2f}%"
    )

    print()


if __name__ == "__main__":

    main()
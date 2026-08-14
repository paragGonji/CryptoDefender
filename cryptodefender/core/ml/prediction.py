import os
import time
import joblib
import numpy as np
import torch
import torch.nn as nn


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "cryptodefender_lstm.pth"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "scaler.pkl"
)

SEQ_LEN = 20

# IMPORTANT:
# These MUST exactly match train_lstm.py
FEATURES = [
    "cpu_total",
    "cpu_user",
    "cpu_system",
    "cpu_idle",
    "cpu_iowait",
    "mem_percent",
    "mem_used",
    "mem_available",
    "processcount_running",
    "processcount_sleeping",
    "processcount_thread",
    "processcount_total",
    "network_lo_rx",
    "network_lo_tx",
]


class CryptoLSTM(nn.Module):

    def __init__(self):

        super().__init__()

        self.lstm = nn.LSTM(
            input_size=len(FEATURES),
            hidden_size=64,
            num_layers=2,
            batch_first=True,
            dropout=0.2
        )

        self.fc1 = nn.Linear(64, 32)

        self.relu = nn.ReLU()

        self.dropout = nn.Dropout(0.2)

        self.fc2 = nn.Linear(32, 1)

    def forward(self, x):

        _, (hidden, _) = self.lstm(x)

        x = hidden[-1]

        x = self.fc1(x)

        x = self.relu(x)

        x = self.dropout(x)

        x = self.fc2(x)

        return x.squeeze(1)


# --------------------------------------------------
# DEVICE
# --------------------------------------------------

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)


# --------------------------------------------------
# MODEL
# --------------------------------------------------

model = CryptoLSTM().to(device)


checkpoint = torch.load(
    MODEL_PATH,
    map_location=device
)

model.load_state_dict(checkpoint)

model.eval()


# --------------------------------------------------
# SCALER
# --------------------------------------------------

scaler = joblib.load(SCALER_PATH)


# --------------------------------------------------
# MODEL ACCURACY
# --------------------------------------------------

MODEL_ACCURACY = 96.94


# --------------------------------------------------
# PREDICTION FUNCTION
# --------------------------------------------------

def predict_mining(samples):

    """
    samples must contain exactly 20 samples.

    Each sample:

    {
        cpu_total,
        cpu_user,
        cpu_system,
        cpu_idle,
        cpu_iowait,
        mem_percent,
        mem_used,
        mem_available,
        processcount_running,
        processcount_sleeping,
        processcount_thread,
        processcount_total,
        network_lo_rx,
        network_lo_tx
    }
    """

    if len(samples) < SEQ_LEN:

        return {
            "prediction": "Collecting Data",
            "prediction_label": "Collecting Data",
            "threat_score": 0,
            "accuracy": MODEL_ACCURACY
        }


    # --------------------------------------------------
    # Take latest 20 samples
    # --------------------------------------------------

    samples = samples[-SEQ_LEN:]


    # --------------------------------------------------
    # Create feature matrix
    # --------------------------------------------------

    data = []

    for sample in samples:

        row = [
            float(sample.get(feature, 0))
            for feature in FEATURES
        ]

        data.append(row)


    data = np.array(
        data,
        dtype=np.float32
    )


    # --------------------------------------------------
    # SCALE
    # --------------------------------------------------

    scaled = scaler.transform(data)


    # --------------------------------------------------
    # TENSOR
    # --------------------------------------------------

    tensor = torch.tensor(
        scaled,
        dtype=torch.float32
    ).unsqueeze(0).to(device)


    # Shape:

    # 1 x 20 x 14


    # --------------------------------------------------
    # MODEL PREDICTION
    # --------------------------------------------------

    with torch.no_grad():

        output = model(tensor)

        probability = torch.sigmoid(output).item()


    threat_score = round(
        probability * 100,
        2
    )


    # --------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------

    if probability >= 0.70:

        prediction_label = "High Risk"

    elif probability >= 0.40:

        prediction_label = "Suspicious"

    else:

        prediction_label = "Normal"


    return {

        "prediction": prediction_label,

        "prediction_label": prediction_label,

        "threat_score": threat_score,

        "raw_score": round(
            probability,
            4
        ),

        "accuracy": MODEL_ACCURACY

    }
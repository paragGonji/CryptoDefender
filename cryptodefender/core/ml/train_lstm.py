import os
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from torch.utils.data import TensorDataset, DataLoader


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

NORMAL_FILE = os.path.join(BASE_DIR, "final-normal-data-set.csv")
ANORMAL_FILE = os.path.join(BASE_DIR, "final-anormal-data-set.csv")

SEQ_LEN = 20
BATCH_SIZE = 64
EPOCHS = 20

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


print("Loading datasets...")

normal = pd.read_csv(NORMAL_FILE, low_memory=False)
anormal = pd.read_csv(ANORMAL_FILE, low_memory=False)

normal["label"] = 0
anormal["label"] = 1

df = pd.concat(
    [normal, anormal],
    ignore_index=True
)

print("Total rows:", len(df))


# -----------------------------
# Select features
# -----------------------------

missing = [
    col for col in FEATURES
    if col not in df.columns
]

if missing:
    print("Missing columns:", missing)
    raise SystemExit


df = df[FEATURES + ["label", "timestamp"]]

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

df = df.sort_values("timestamp")

for col in FEATURES:
    df[col] = pd.to_numeric(
        df[col],
        errors="coerce"
    )

df = df.dropna()


print("Rows after cleaning:", len(df))


# -----------------------------
# Scale features
# -----------------------------

scaler = MinMaxScaler()

X = scaler.fit_transform(
    df[FEATURES]
)

y = df["label"].values


joblib.dump(
    scaler,
    os.path.join(BASE_DIR, "scaler.pkl")
)


# -----------------------------
# Create sequences
# -----------------------------

X_sequences = []
y_sequences = []

for i in range(len(X) - SEQ_LEN):

    X_sequences.append(
        X[i:i + SEQ_LEN]
    )

    y_sequences.append(
        y[i + SEQ_LEN]
    )


X_sequences = np.array(
    X_sequences,
    dtype=np.float32
)

y_sequences = np.array(
    y_sequences,
    dtype=np.float32
)


print("Sequences:", len(X_sequences))


# -----------------------------
# Train / test
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X_sequences,
    y_sequences,
    test_size=0.2,
    random_state=42,
    stratify=y_sequences
)


X_train = torch.tensor(X_train)
X_test = torch.tensor(X_test)

y_train = torch.tensor(y_train)
y_test = torch.tensor(y_test)


train_loader = DataLoader(
    TensorDataset(X_train, y_train),
    batch_size=BATCH_SIZE,
    shuffle=True
)


# -----------------------------
# LSTM
# -----------------------------

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

        return self.fc2(x).squeeze(1)


# -----------------------------
# Device
# -----------------------------

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("Device:", device)


model = CryptoLSTM().to(device)


criterion = nn.BCEWithLogitsLoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=0.001
)


# -----------------------------
# Training
# -----------------------------

for epoch in range(EPOCHS):

    model.train()

    total_loss = 0

    for batch_x, batch_y in train_loader:

        batch_x = batch_x.to(device)
        batch_y = batch_y.to(device)

        optimizer.zero_grad()

        output = model(batch_x)

        loss = criterion(
            output,
            batch_y
        )

        loss.backward()

        optimizer.step()

        total_loss += loss.item()

    avg_loss = (
        total_loss /
        len(train_loader)
    )

    print(
        f"Epoch {epoch + 1}/{EPOCHS} "
        f"- Loss: {avg_loss:.4f}"
    )


# -----------------------------
# Evaluation
# -----------------------------

model.eval()

with torch.no_grad():

    test_x = X_test.to(device)

    output = model(test_x)

    probabilities = torch.sigmoid(output)

    predictions = (
        probabilities >= 0.5
    ).float()

    accuracy = (
        predictions.cpu() == y_test
    ).float().mean()

print()
print("==============================")
print("MODEL RESULT")
print("==============================")
print(
    f"Accuracy: {accuracy.item() * 100:.2f}%"
)


# -----------------------------
# Save model
# -----------------------------

model_path = os.path.join(
    BASE_DIR,
    "cryptodefender_lstm.pth"
)

torch.save(
    model.state_dict(),
    model_path
)

print()
print("Model saved:")
print(model_path)

print()
print("Scaler saved:")
print(
    os.path.join(
        BASE_DIR,
        "scaler.pkl"
    )
)
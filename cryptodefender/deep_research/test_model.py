import os
import pickle
import torch
import joblib
from hybrid_model import HybridMiningDetector


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "hybrid_mining_detector.pt"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "model",
    "scaler.pkl"
)


print("MODEL:")
print(MODEL_PATH)

print(
    "Exists:",
    os.path.exists(MODEL_PATH)
)


checkpoint = torch.load(
    MODEL_PATH,
    map_location="cpu",
    weights_only=False
)

print(
    "Checkpoint keys:",
    checkpoint.keys()
)

print(
    "Features:",
    checkpoint["features"]
)


model = HybridMiningDetector(
    input_size=len(
        checkpoint["features"]
    )
)

model.load_state_dict(
    checkpoint["model_state_dict"]
)

model.eval()


scaler = joblib.load(
    SCALER_PATH
)


print(
    "Scaler loaded:",
    type(scaler).__name__
)

print(
    "MODEL TEST PASSED"
)
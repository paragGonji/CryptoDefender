import os
import joblib
import torch
import numpy as np

from .hybrid_model import HybridMiningDetector


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


FEATURES = [
    "cpu",
    "memory",
    "threads",
    "process_age",
    "known_miner",
    "suspicious_path",
    "unknown_exe"
]


class MiningDetector:

    def __init__(self):

        self.device = torch.device(
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        checkpoint = torch.load(
            MODEL_PATH,
            map_location=self.device
        )

        self.model = HybridMiningDetector(
            input_size=len(FEATURES)
        )

        self.model.load_state_dict(
            checkpoint["model_state_dict"]
        )

        self.model.to(
            self.device
        )

        self.model.eval()

        self.scaler = joblib.load(
            SCALER_PATH
        )


    def predict(self, process):

        known_miner = int(
            process.get(
                "known_miner",
                0
            )
        )

        # Hard signature detection
        if known_miner == 1:

            return {
                "prediction": "MINING",
                "confidence": 1.0,
                "reason": "Known cryptocurrency miner"
            }


        values = np.array(
            [[
                process.get("cpu", 0),
                process.get("memory", 0),
                process.get("threads", 0),
                process.get("process_age", 0),
                process.get("known_miner", 0),
                process.get("suspicious_path", 0),
                process.get("unknown_exe", 0)
            ]],
            dtype=np.float32
        )


        values = self.scaler.transform(
            values
        )


        values = values.reshape(
            1,
            1,
            len(FEATURES)
        )


        tensor = torch.tensor(
            values,
            dtype=torch.float32
        ).to(self.device)


        with torch.no_grad():

            logits, reconstructed = self.model(
                tensor
            )

            probabilities = torch.softmax(
                logits,
                dim=1
            )

            prediction = torch.argmax(
                probabilities,
                dim=1
            ).item()

            confidence = probabilities[
                0,
                prediction
            ].item()


        if prediction == 1:

            result = "MINING"

        else:

            result = "SAFE"


        return {

            "prediction": result,

            "confidence": round(
                confidence,
                4
            ),

            "reason":
                "Hybrid CNN-LSTM-Autoencoder"
        }
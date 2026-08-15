import json
import os
from datetime import timedelta

import joblib
import numpy as np

from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .models import ScanResult


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "model"
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
# GLOBAL STATE
# ============================================================

latest_result = {
    "type": "waiting",
    "status": "Waiting for scan...",
    "miners": [],
    "suspicious": [],
    "top5": [],

    "risk_score": 0,
    "model_score": 0,
    "model_accuracy": 0,

    "autoencoder_score": 0,

    # Calculation information
    "rule_score": 0,
    "rule_risk": 0,
    "rule_weight": 35,

    "ml_weight": 50,
    "ml_contribution": 0,

    "anomaly_weight": 15,
    "anomaly_contribution": 0,

    "hybrid_calculation": (
        "Rule Risk × 35% + ML Score × 50% "
        "+ Autoencoder Anomaly × 15%"
    ),

    "accuracy_source": (
        "Model evaluation/test accuracy from metadata.json"
    ),

    "message": "Download and run the scanner."
}


# ============================================================
# PROCESS RULES
# ============================================================

MINER_NAMES = [
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
    "xmr-stak"
]


IGNORE_LIST = {
    "windowsterminal.exe",
    "chrome.exe",
    "explorer.exe",
    "dwm.exe",
    "system",
    "system idle process",
    "wmiprvse.exe",
    "svchost.exe"
}


# ============================================================
# ML GLOBALS
# ============================================================

_model = None
_scaler = None
_metadata = None


# ============================================================
# LOAD MODEL
# ============================================================

def load_ml_model():

    global _model
    global _scaler
    global _metadata

    if _model is not None:
        return True

    if not os.path.exists(MODEL_PATH):

        print(
            "[ML] Model not found:",
            MODEL_PATH
        )

        return False

    try:

        import torch

        from .hybrid_model import HybridMiningDetector

        checkpoint = torch.load(
            MODEL_PATH,
            map_location="cpu",
            weights_only=False
        )

        if not isinstance(checkpoint, dict):

            print(
                "[ML] Invalid checkpoint format."
            )

            return False

        state_dict = checkpoint.get(
            "model_state_dict"
        )

        features = checkpoint.get(
            "features"
        )

        if state_dict is None:

            print(
                "[ML] model_state_dict missing."
            )

            return False

        if not features:

            print(
                "[ML] Feature list missing."
            )

            return False

        print(
            "[ML] Model features:",
            features
        )

        _model = HybridMiningDetector(
            input_size=len(features)
        )

        _model.load_state_dict(
            state_dict
        )

        _model.eval()

        if os.path.exists(SCALER_PATH):

            _scaler = joblib.load(
                SCALER_PATH
            )

            print(
                "[ML] Scaler loaded."
            )

        else:

            print(
                "[ML] scaler.pkl not found."
            )

        if os.path.exists(METADATA_PATH):

            with open(
                METADATA_PATH,
                "r",
                encoding="utf-8"
            ) as f:

                _metadata = json.load(f)

            print(
                "[ML] Metadata loaded."
            )

        print(
            "[ML] Hybrid CNN + LSTM + Autoencoder "
            "model loaded successfully."
        )

        return True

    except Exception as e:

        print(
            "[ML] Model loading error:",
            repr(e)
        )

        _model = None
        _scaler = None
        _metadata = None

        return False


# ============================================================
# MODEL ACCURACY
# ============================================================

def get_model_accuracy():

    if not isinstance(
        _metadata,
        dict
    ):

        return 0.0

    possible_keys = [
        "accuracy",
        "model_accuracy",
        "test_accuracy",
        "final_accuracy",
        "best_validation_accuracy"
    ]

    for key in possible_keys:

        value = _metadata.get(
            key
        )

        if value is not None:

            try:

                value = float(value)

                # Metadata may contain:
                #
                # 94.55
                #
                # or:
                #
                # 0.9455

                if value <= 1:

                    value *= 100

                return round(
                    value,
                    2
                )

            except (
                TypeError,
                ValueError
            ):

                pass

    return 0.0


# ============================================================
# PROCESS FEATURES
# ============================================================

def create_ml_vector(process):

    name = (
        process.get("name")
        or ""
    ).lower()

    cpu = float(
        process.get(
            "cpu",
            0
        )
        or 0
    )

    memory = float(
        process.get(
            "memory",
            process.get(
                "mem",
                0
            )
        )
        or 0
    )

    threads = float(
        process.get(
            "threads",
            1
        )
        or 1
    )

    process_age = float(
        process.get(
            "process_age",
            0
        )
        or 0
    )

    known_miner = int(
        process.get(
            "known_miner",
            0
        )
        or 0
    )

    suspicious_path = int(
        process.get(
            "suspicious_path",
            0
        )
        or 0
    )

    unknown_exe = int(
        process.get(
            "unknown_exe",
            0
        )
        or 0
    )

    return np.array(
        [
            cpu,
            memory,
            threads,
            process_age,
            known_miner,
            suspicious_path,
            unknown_exe
        ],
        dtype=np.float32
    )


# ============================================================
# ML PREDICTION
# ============================================================

def ml_predict(processes):

    if not processes:

        return {
            "score": 0.0,
            "anomaly": 0.0,
            "detected": False
        }

    if not load_ml_model():

        return {
            "score": 0.0,
            "anomaly": 0.0,
            "detected": False
        }

    try:

        import torch

        vectors = [
            create_ml_vector(p)
            for p in processes
        ]

        x = np.asarray(
            vectors,
            dtype=np.float32
        )

        # ====================================================
        # SAME SCALER USED DURING TRAINING
        # ====================================================

        if _scaler is not None:

            x = _scaler.transform(
                x
            )

        # ====================================================
        # MODEL INPUT
        #
        # [batch, sequence_length, features]
        #
        # sequence_length = 1
        # ====================================================

        tensor = torch.tensor(
            x,
            dtype=torch.float32
        ).unsqueeze(1)

        _model.eval()

        with torch.no_grad():

            logits, reconstructed = _model(
                tensor
            )

            # =================================================
            # CNN + LSTM CLASSIFICATION
            # =================================================

            probabilities = torch.softmax(
                logits,
                dim=1
            )

            mining_probability = (
                probabilities[:, 1]
            )

            score = float(
                mining_probability.mean().item()
            )

            # =================================================
            # AUTOENCODER RECONSTRUCTION
            # =================================================

            original = tensor[:, -1, :]

            reconstruction_error = torch.mean(
                (
                    reconstructed
                    -
                    original
                ) ** 2,
                dim=1
            )

            raw_anomaly = float(
                reconstruction_error.mean().item()
            )

        # ====================================================
        # ANOMALY NORMALIZATION
        #
        # Existing behavior retained.
        # ====================================================

        anomaly = min(
            raw_anomaly / 4.5,
            1.0
        )

        anomaly = max(
            0.0,
            anomaly
        )

        # ====================================================
        # ML SCORE LIMIT
        # ====================================================

        score = max(
            0.0,
            min(
                score,
                1.0
            )
        )

        return {

            "score":
                round(
                    score,
                    4
                ),

            "anomaly":
                round(
                    anomaly,
                    4
                ),

            "detected":
                score >= 0.65
        }

    except Exception as e:

        print(
            "[ML] Prediction error:",
            repr(e)
        )

        return {
            "score": 0.0,
            "anomaly": 0.0,
            "detected": False
        }


# ============================================================
# PROCESS ANALYSIS
# ============================================================

def analyze_processes(processes):

    detected_miners = []

    suspicious = []

    clean_processes = []

    rule_score = 0

    # ========================================================
    # PROCESS LOOP
    # ========================================================

    for p in processes:

        name = (
            p.get("name")
            or ""
        ).lower()

        if not name:
            continue

        if name in IGNORE_LIST:
            continue

        # ====================================================
        # CPU
        # ====================================================

        try:

            cpu = float(
                p.get(
                    "cpu",
                    0
                )
                or 0
            )

        except Exception:

            cpu = 0.0

        # ====================================================
        # MEMORY
        # ====================================================

        try:

            memory = float(
                p.get(
                    "memory",
                    p.get(
                        "mem",
                        0
                    )
                )
                or 0
            )

        except Exception:

            memory = 0.0

        # ====================================================
        # OTHER FEATURES
        # ====================================================

        try:

            threads = int(
                p.get(
                    "threads",
                    1
                )
                or 1
            )

        except Exception:

            threads = 1

        try:

            process_age = float(
                p.get(
                    "process_age",
                    0
                )
                or 0
            )

        except Exception:

            process_age = 0.0

        known_miner = int(
            p.get(
                "known_miner",
                0
            )
            or 0
        )

        suspicious_path = int(
            p.get(
                "suspicious_path",
                0
            )
            or 0
        )

        unknown_exe = int(
            p.get(
                "unknown_exe",
                0
            )
            or 0
        )

        clean_processes.append({

            "name":
                name,

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
                unknown_exe
        })

        # ====================================================
        # KNOWN MINER
        # ====================================================

        miner_match = None

        for miner in MINER_NAMES:

            if miner in name:

                miner_match = miner

                break

        if miner_match:

            detected_miners.append(
                f"{name} — known mining tool ({miner_match})"
            )

            rule_score += 85

            continue

        # ====================================================
        # HIGH CPU
        # ====================================================

        if cpu >= 80:

            suspicious.append(
                f"{name} — very high CPU ({cpu:.1f}%)"
            )

            rule_score += 30

        elif cpu >= 60:

            suspicious.append(
                f"{name} — high CPU ({cpu:.1f}%)"
            )

            rule_score += 20

        # ====================================================
        # SUSPICIOUS PATH
        # ====================================================

        if suspicious_path:

            suspicious.append(
                f"{name} — suspicious executable location"
            )

            rule_score += 10

        # ====================================================
        # UNKNOWN EXE
        # ====================================================

        if unknown_exe:

            suspicious.append(
                f"{name} — unknown executable"
            )

            rule_score += 5

    # ========================================================
    # TOP CPU PROCESSES
    # ========================================================

    top5 = sorted(
        clean_processes,
        key=lambda x: x["cpu"],
        reverse=True
    )[:5]

    top5_display = [

        (
            f"{p['name']} — "
            f"CPU {p['cpu']:.1f}% / "
            f"Memory {p['memory']:.1f}%"
        )

        for p in top5
    ]

    # ========================================================
    # ML
    # ========================================================

    ml = ml_predict(
        clean_processes
    )

    ml_score = ml[
        "score"
    ]

    anomaly_score = ml[
        "anomaly"
    ]

    # ========================================================
    # RULE SCORE
    # ========================================================

    rule_normalized = min(
        rule_score / 100.0,
        1.0
    )

    # ========================================================
    # HYBRID SCORE
    #
    # 35% RULES
    # 50% CNN/LSTM CLASSIFICATION
    # 15% AUTOENCODER ANOMALY
    #
    # IMPORTANT:
    # These are actual values generated from the
    # current scanner data and ML model.
    # ========================================================

    RULE_WEIGHT = 0.35
    ML_WEIGHT = 0.50
    ANOMALY_WEIGHT = 0.15

    rule_contribution = (
        rule_normalized
        *
        RULE_WEIGHT
    )

    ml_contribution = (
        ml_score
        *
        ML_WEIGHT
    )

    anomaly_contribution = (
        anomaly_score
        *
        ANOMALY_WEIGHT
    )

    final_score = (

        rule_contribution

        +

        ml_contribution

        +

        anomaly_contribution
    )

    final_score = max(
        0.0,
        min(
            final_score,
            1.0
        )
    )

    # ========================================================
    # KNOWN MINER OVERRIDE
    # ========================================================

    if detected_miners:

        final_score = max(
            final_score,
            0.95
        )

    # ========================================================
    # FINAL DECISION
    # ========================================================

    mining_detected = (

        bool(
            detected_miners
        )

        or ml["detected"]

        or final_score >= 0.65
    )

    # ========================================================
    # STATUS
    # ========================================================

    if mining_detected:

        status = (
            "⚠️ Mining Activity Detected!"
        )

        result_type = (
            "miner_found"
        )

        message = (
            "Crypto-mining activity was "
            "detected from process behaviour."
        )

    elif final_score >= 0.35:

        status = (
            "⚠️ Suspicious Process Activity"
        )

        result_type = (
            "suspicious"
        )

        message = (
            "Some process behaviour is unusual, "
            "but mining was not confirmed."
        )

    else:

        status = (
            "✅ System Safe"
        )

        result_type = (
            "safe"
        )

        message = (
            "No cryptocurrency mining process "
            "was detected."
        )

    # ========================================================
    # MODEL ACCURACY
    # ========================================================

    model_accuracy = get_model_accuracy()

    # ========================================================
    # FRONTEND CALCULATION VALUES
    # ========================================================

    rule_risk_percent = (
        rule_normalized * 100
    )

    ml_score_percent = (
        ml_score * 100
    )

    anomaly_score_percent = (
        anomaly_score * 100
    )

    hybrid_risk_percent = (
        final_score * 100
    )

    rule_contribution_percent = (
        rule_contribution * 100
    )

    ml_contribution_percent = (
        ml_contribution * 100
    )

    anomaly_contribution_percent = (
        anomaly_contribution * 100
    )

    # ========================================================
    # HUMAN-READABLE CALCULATION
    # ========================================================

    hybrid_calculation = (
        f"({rule_risk_percent:.2f}% × 35%) + "
        f"({ml_score_percent:.2f}% × 50%) + "
        f"({anomaly_score_percent:.2f}% × 15%) = "
        f"{hybrid_risk_percent:.2f}%"
    )

    # ========================================================
    # RESULT
    # ========================================================

    return {

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        "type":
            result_type,

        "status":
            status,

        "message":
            message,

        # ----------------------------------------------------
        # PROCESS INFORMATION
        # ----------------------------------------------------

        "miners":
            detected_miners,

        "suspicious":
            suspicious[:15],

        "top5":
            top5_display,

        # ----------------------------------------------------
        # MAIN FRONTEND VALUES
        # ----------------------------------------------------

        "risk_score":
            round(
                hybrid_risk_percent,
                2
            ),

        "model_score":
            round(
                ml_score_percent,
                2
            ),

        "model_accuracy":
            round(
                model_accuracy,
                2
            ),

        # ----------------------------------------------------
        # AUTOENCODER
        #
        # Kept in backend for calculation.
        # Your HTML does not need to display it.
        # ----------------------------------------------------

        "autoencoder_score":
            round(
                anomaly_score_percent,
                2
            ),

        # ----------------------------------------------------
        # RULE CALCULATION
        # ----------------------------------------------------

        "rule_score":
            round(
                rule_score,
                2
            ),

        "rule_risk":
            round(
                rule_risk_percent,
                2
            ),

        "rule_weight":
            35,

        "rule_contribution":
            round(
                rule_contribution_percent,
                2
            ),

        # ----------------------------------------------------
        # ML CALCULATION
        # ----------------------------------------------------

        "ml_weight":
            50,

        "ml_contribution":
            round(
                ml_contribution_percent,
                2
            ),

        # ----------------------------------------------------
        # AUTOENCODER CALCULATION
        # ----------------------------------------------------

        "anomaly_weight":
            15,

        "anomaly_contribution":
            round(
                anomaly_contribution_percent,
                2
            ),

        # ----------------------------------------------------
        # FINAL HYBRID CALCULATION
        # ----------------------------------------------------

        "hybrid_calculation":
            hybrid_calculation,

        "hybrid_formula":
            (
                "Rule Risk × 35% + "
                "ML Score × 50% + "
                "Autoencoder Anomaly × 15%"
            ),

        # ----------------------------------------------------
        # ACCURACY INFORMATION
        # ----------------------------------------------------

        "accuracy_source":
            (
                "Model evaluation/test accuracy "
                "loaded from metadata.json"
            )
    }


# ============================================================
# SCAN API
# ============================================================

@csrf_exempt
def scan_result(request):

    global latest_result

    if request.method != "POST":

        return JsonResponse(
            {
                "error": "POST required"
            },
            status=405
        )

    try:

        data = json.loads(
            request.body.decode(
                "utf-8"
            )
        )

    except Exception as e:

        return JsonResponse(
            {
                "error": "Invalid JSON",
                "details": str(e)
            },
            status=400
        )

    processes = data.get(
        "processes",
        []
    )

    if not isinstance(
        processes,
        list
    ):

        return JsonResponse(
            {
                "error":
                    "processes must be a list"
            },
            status=400
        )

    # ========================================================
    # ANALYZE
    # ========================================================

    latest_result = analyze_processes(
        processes
    )

    # ========================================================
    # DATABASE
    # ========================================================

    try:

        ScanResult.objects.create(
            result=json.dumps(
                latest_result
            )
        )

    except Exception as e:

        print(
            "[DB] Could not save ScanResult:",
            e
        )

    # ========================================================
    # PREVENTION
    # ========================================================

    prevention_unlocked = (
        latest_result["type"]
        ==
        "miner_found"
    )

    request.session[
        "prevention_unlocked"
    ] = prevention_unlocked

    request.session.modified = True

    # ========================================================
    # RESPONSE
    #
    # All values here are generated dynamically from the
    # current scanner result.
    # ========================================================

    return JsonResponse(
        {

            "success":
                True,

            "status":
                latest_result[
                    "status"
                ],

            "type":
                latest_result[
                    "type"
                ],

            # ------------------------------------------------
            # MAIN VALUES
            # ------------------------------------------------

            "risk_score":
                latest_result[
                    "risk_score"
                ],

            "model_score":
                latest_result[
                    "model_score"
                ],

            "model_accuracy":
                latest_result[
                    "model_accuracy"
                ],

            # ------------------------------------------------
            # CALCULATION VALUES
            # ------------------------------------------------

            "rule_score":
                latest_result[
                    "rule_score"
                ],

            "rule_risk":
                latest_result[
                    "rule_risk"
                ],

            "rule_weight":
                latest_result[
                    "rule_weight"
                ],

            "rule_contribution":
                latest_result[
                    "rule_contribution"
                ],

            "ml_weight":
                latest_result[
                    "ml_weight"
                ],

            "ml_contribution":
                latest_result[
                    "ml_contribution"
                ],

            "anomaly_weight":
                latest_result[
                    "anomaly_weight"
                ],

            "anomaly_contribution":
                latest_result[
                    "anomaly_contribution"
                ],

            "hybrid_calculation":
                latest_result[
                    "hybrid_calculation"
                ],

            "hybrid_formula":
                latest_result[
                    "hybrid_formula"
                ],

            "accuracy_source":
                latest_result[
                    "accuracy_source"
                ],

            # ------------------------------------------------
            # BACKEND ANOMALY VALUE
            # ------------------------------------------------

            "autoencoder_score":
                latest_result[
                    "autoencoder_score"
                ],

            # ------------------------------------------------
            # PROCESSES
            # ------------------------------------------------

            "miners":
                latest_result[
                    "miners"
                ],

            "suspicious":
                latest_result[
                    "suspicious"
                ],

            "top5":
                latest_result[
                    "top5"
                ],

            "message":
                latest_result[
                    "message"
                ],

            # ------------------------------------------------
            # PREVENTION
            # ------------------------------------------------

            "prevention_unlocked":
                prevention_unlocked
        }
    )


# ============================================================
# DEEP RESEARCH PAGE
# ============================================================

def deep_research(request):

    # ========================================================
    # LOAD MODEL
    # ========================================================

    load_ml_model()

    # ========================================================
    # GET LATEST SCAN
    # ========================================================

    latest = (
        ScanResult.objects
        .order_by(
            "-created_at"
        )
        .first()
    )

    parsed_result = None

    if latest:

        if (
            timezone.now()
            -
            latest.created_at
            >
            timedelta(
                minutes=5
            )
        ):

            latest.delete()

        else:

            try:

                parsed_result = json.loads(
                    latest.result
                )

            except Exception:

                parsed_result = None

    # ========================================================
    # FALLBACK
    # ========================================================

    if parsed_result is None:

        parsed_result = latest_result

    # ========================================================
    # CURRENT MODEL ACCURACY
    #
    # Accuracy is loaded from the trained model's
    # metadata, not invented by the frontend.
    # ========================================================

    if isinstance(
        parsed_result,
        dict
    ):

        parsed_result[
            "model_accuracy"
        ] = get_model_accuracy()

        parsed_result[
            "accuracy_source"
        ] = (
            "Model evaluation/test accuracy "
            "loaded from metadata.json"
        )

    # ========================================================
    # PREVENTION
    # ========================================================

    prevention_unlocked = (

        parsed_result

        and

        parsed_result.get(
            "type"
        )
        ==
        "miner_found"
    )

    request.session[
        "prevention_unlocked"
    ] = bool(
        prevention_unlocked
    )

    request.session.modified = True

    # ========================================================
    # RENDER
    # ========================================================

    return render(
        request,
        "core/deep_research.html",
        {
            "result":
                parsed_result,

            "prevention_unlocked":
                bool(
                    prevention_unlocked
                )
        }
    )


# ============================================================
# STATUS API
# ============================================================

def scan_status(request):

    load_ml_model()

    result = dict(
        latest_result
    )

    # ========================================================
    # CURRENT MODEL ACCURACY
    # ========================================================

    result[
        "model_accuracy"
    ] = get_model_accuracy()

    result[
        "accuracy_source"
    ] = (
        "Model evaluation/test accuracy "
        "loaded from metadata.json"
    )

    return JsonResponse(
        result
    )
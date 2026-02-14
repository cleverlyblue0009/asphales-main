"""Train multilingual phishing ML model on all available datasets."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.ml_classifier import DATASET_PATHS, MODEL_PATH, MLPhishingClassifier

if __name__ == "__main__":
    clf = MLPhishingClassifier()
    clf.train(DATASET_PATHS, Path(MODEL_PATH))
    print("Training complete")

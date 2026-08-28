from pathlib import Path
import json

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification
)


class CodeBERTClassifier:

    def __init__(self, model_path: str):

        self.model_path = Path(model_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"CodeBERT model directory not found: "
                f"{self.model_path}"
            )

        # --------------------------------------------------
        # Device
        # --------------------------------------------------

        self.device = torch.device(
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        # --------------------------------------------------
        # Load tokenizer
        # --------------------------------------------------

        self.tokenizer = AutoTokenizer.from_pretrained(
            str(self.model_path),
            local_files_only=True
        )

        # --------------------------------------------------
        # Load trained CodeBERT classifier
        # --------------------------------------------------

        self.model = (
            AutoModelForSequenceClassification
            .from_pretrained(
                str(self.model_path),
                local_files_only=True
            )
        )

        self.model.to(self.device)
        self.model.eval()

        # --------------------------------------------------
        # Load inference configuration
        # --------------------------------------------------

        inference_config_path = (
            self.model_path / "inference_config.json"
        )

        if inference_config_path.exists():

            with open(
                inference_config_path,
                "r",
                encoding="utf-8"
            ) as file:

                config = json.load(file)

        else:
            # Fallback values matching the trained model
            config = {
                "max_length": 512,
                "stride": 128,
                "max_chunks_per_function": 16,
                "chunk_aggregation": "mean_probability",
                "classification_threshold": 0.5,
                "labels": {
                    "0": "non-vulnerable",
                    "1": "vulnerable"
                }
            }

        # --------------------------------------------------
        # Model inference settings
        # --------------------------------------------------

        self.max_length = config.get(
            "max_length",
            512
        )

        self.stride = config.get(
            "stride",
            128
        )

        self.max_chunks = config.get(
            "max_chunks_per_function",
            16
        )

        self.aggregation = config.get(
            "chunk_aggregation",
            "mean_probability"
        )

        self.threshold = config.get(
            "classification_threshold",
            0.5
        )

        # --------------------------------------------------
        # Label mapping
        # --------------------------------------------------

        configured_labels = config.get(
            "labels",
            {
                "0": "non-vulnerable",
                "1": "vulnerable"
            }
        )

        self.labels = {
            int(key): value
            for key, value in configured_labels.items()
        }

    # ======================================================
    # Prediction
    # ======================================================

    def predict(
        self,
        code: str
    ) -> dict:

        if not code or not code.strip():
            raise ValueError(
                "Code cannot be empty."
            )

        # --------------------------------------------------
        # Tokenize source code into overlapping chunks
        # --------------------------------------------------

        encoded = self.tokenizer(
            code,
            truncation=True,
            max_length=self.max_length,
            stride=self.stride,
            return_overflowing_tokens=True,
            padding=False,
            return_tensors=None
        )

        input_ids = encoded["input_ids"]
        attention_masks = encoded["attention_mask"]

        # --------------------------------------------------
        # Limit number of chunks
        # --------------------------------------------------

        input_ids = input_ids[
            :self.max_chunks
        ]

        attention_masks = attention_masks[
            :self.max_chunks
        ]

        chunk_probabilities = []

        # --------------------------------------------------
        # Run model on every chunk
        # --------------------------------------------------

        for ids, mask in zip(
            input_ids,
            attention_masks
        ):

            input_tensor = torch.tensor(
                [ids],
                dtype=torch.long,
                device=self.device
            )

            mask_tensor = torch.tensor(
                [mask],
                dtype=torch.long,
                device=self.device
            )

            with torch.no_grad():

                outputs = self.model(
                    input_ids=input_tensor,
                    attention_mask=mask_tensor
                )

            probabilities = torch.softmax(
                outputs.logits,
                dim=-1
            )[0]

            # Class 1 = vulnerable
            vulnerable_probability = (
                probabilities[1].item()
            )

            chunk_probabilities.append(
                vulnerable_probability
            )

        if not chunk_probabilities:
            raise RuntimeError(
                "CodeBERT produced no chunks "
                "for the supplied code."
            )

        # --------------------------------------------------
        # Aggregate chunk probabilities
        # --------------------------------------------------

        if self.aggregation == "mean_probability":

            vulnerable_probability = (
                sum(chunk_probabilities)
                / len(chunk_probabilities)
            )

        else:

            raise ValueError(
                f"Unsupported aggregation method: "
                f"{self.aggregation}"
            )

        non_vulnerable_probability = (
            1.0 - vulnerable_probability
        )

        # --------------------------------------------------
        # Final classification
        # --------------------------------------------------

        predicted_label = (
            1
            if vulnerable_probability >= self.threshold
            else 0
        )

        # Confidence = probability of predicted class
        confidence = (
            vulnerable_probability
            if predicted_label == 1
            else non_vulnerable_probability
        )

        # --------------------------------------------------
        # Return result
        # --------------------------------------------------

        return {
            "label": predicted_label,

            "label_name": self.labels[
                predicted_label
            ],

            "vulnerable": (
                predicted_label == 1
            ),

            "confidence": confidence,

            "vulnerable_probability": (
                vulnerable_probability
            ),

            "non_vulnerable_probability": (
                non_vulnerable_probability
            ),

            "chunks_analyzed": (
                len(chunk_probabilities)
            ),

            "threshold": self.threshold,

            "device": str(self.device)
        }
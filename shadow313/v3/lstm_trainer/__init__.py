"""shadow313.v3.lstm_trainer — LSTM head trainer for C2 beacon detection."""
from .lstm_trainer import LSTMHeadTrainer, generate_c2_beacon_sequence, generate_benign_sequence

__all__ = ["LSTMHeadTrainer", "generate_c2_beacon_sequence", "generate_benign_sequence"]
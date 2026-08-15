import torch
import torch.nn as nn


class CNNLSTMEncoder(nn.Module):

    def __init__(self, input_size, hidden_size=64):
        super().__init__()

        self.cnn = nn.Sequential(
            nn.Conv1d(
                in_channels=input_size,
                out_channels=64,
                kernel_size=3,
                padding=1
            ),
            nn.ReLU(),

            nn.Conv1d(
                in_channels=64,
                out_channels=64,
                kernel_size=3,
                padding=1
            ),
            nn.ReLU()
        )

        self.lstm = nn.LSTM(
            input_size=64,
            hidden_size=hidden_size,
            batch_first=True,
            bidirectional=True
        )

    def forward(self, x):

        # x:
        # [batch, sequence, features]

        x = x.transpose(1, 2)

        x = self.cnn(x)

        x = x.transpose(1, 2)

        output, _ = self.lstm(x)

        return output[:, -1, :]


class ProcessAutoencoder(nn.Module):

    def __init__(self, input_size, latent_size=32):

        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),

            nn.Linear(64, latent_size),
            nn.ReLU()
        )

        self.decoder = nn.Sequential(
            nn.Linear(latent_size, 64),
            nn.ReLU(),

            nn.Linear(64, input_size)
        )

    def forward(self, x):

        z = self.encoder(x)

        reconstructed = self.decoder(z)

        return reconstructed


class HybridMiningDetector(nn.Module):

    def __init__(
        self,
        input_size,
        hidden_size=64
    ):

        super().__init__()

        self.encoder = CNNLSTMEncoder(
            input_size,
            hidden_size
        )

        self.autoencoder = ProcessAutoencoder(
            input_size
        )

        self.classifier = nn.Sequential(

            nn.Linear(
                hidden_size * 2 + input_size,
                128
            ),

            nn.ReLU(),

            nn.Dropout(0.25),

            nn.Linear(128, 64),

            nn.ReLU(),

            nn.Linear(64, 2)
        )

    def forward(self, x):

        sequence_features = self.encoder(x)

        last_features = x[:, -1, :]

        reconstructed = self.autoencoder(last_features)

        combined = torch.cat(
            [
                sequence_features,
                reconstructed
            ],
            dim=1
        )

        logits = self.classifier(combined)

        return logits, reconstructed
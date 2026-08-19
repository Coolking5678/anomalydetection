"""
main.py
-------
Entry point for the AI-Based Security Log Anomaly Detector desktop application.

Usage
-----
    python main.py

The application window will open immediately. The first time you run it,
click "⬇ Download Sample" to fetch the SSH_2k.log dataset from Loghub,
or use "Browse…" to select your own .log file.
"""

import logging
import sys

# Configure root logger before any module imports that use it
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

from gui.app_window import AnomalyDetectorApp  # noqa: E402


def main() -> None:
    """Initialise and run the Tkinter event loop."""
    app = AnomalyDetectorApp()
    app.mainloop()


if __name__ == "__main__":
    main()

# BlueDefenderX/utils/logger.py
import logging
import os

def setup_logger(name, log_file, level=logging.INFO):
    """Function to setup a logger."""
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.addHandler(console_handler)

    return logger

# Create a default logger for the application
if not os.path.exists('logs'):
    os.makedirs('logs')
bd_logger = setup_logger('BlueDefenderX', 'logs/app.log')

# Example usage in other modules:
# from utils.logger import bd_logger
# bd_logger.info("This is an info message")
# bd_logger.error("This is an error message")
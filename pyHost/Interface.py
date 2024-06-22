from serial.tools.list_ports import comports
import logging
import numpy as np

from pyHost import Client, MaskableLogger

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger = MaskableLogger(logger)

import binascii
from logging import LoggerAdapter, Logger


def hexlify(buffer: bytes) -> str:
    return binascii.hexlify(buffer, sep=' ')


class LogMask:
    def __init__(self) -> None:
        # 是否屏蔽 log 输出
        self._mask = False

    def filter(self, _):
        return not self._mask

    def mask(self):
        self._mask = True

    def unmask(self):
        self._mask = False


class MaskableLogger(LoggerAdapter):
    def __init__(self, logger: Logger) -> None:
        super().__init__(logger)

        self._mask = LogMask()

        self.logger: Logger
        self.logger.addFilter(self._mask)

    def mask(self) -> None:
        self._mask.mask()

    def unmask(self) -> None:
        self._mask.unmask()

    def getChild(self, suffix: str) -> Logger:
        logger = self.logger.getChild(suffix)
        logger.addFilter(self._mask)
        return logger

import binascii


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

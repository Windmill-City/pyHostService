from Cryptodome.Cipher import AES
from logging import Logger

from pyHostService.Logging import hexlify
from pyHostService import Common


class Cipher:
    def __init__(self, logger: Logger, key: bytes):
        """创建加密器

        Args:
            logger (Logger): 日志记录器
            key (bytes): 密钥
        """
        assert len(key) == Common.AES_CCM_KEY_SIZE

        self.logger = logger.getChild('Cipher')
        self.key = key

    def encrypt(self, data: bytes, nonce: bytes) -> tuple[bytes, bytes]:
        """加密数据

        Args:
            data (bytes): 明文
            nonce (bytes): 随机数

        Returns:
            tuple[bytes, bytes]: CEC-MAC, 密文
        """
        assert len(data) > 0
        assert len(nonce) == Common.AES_CCM_NONCE_SIZE

        # 执行加密
        self.logger.debug(f'Plaintext: {hexlify(data)}')
        cipher = AES.new(self.key, mode=AES.MODE_CCM, nonce=nonce, mac_len=Common.AES_CCM_TAG_SIZE)
        data, tag = cipher.encrypt_and_digest(data)
        self.logger.debug(f'Ciphertext: {hexlify(data)}')
        self.logger.debug(f'Tag: {hexlify(tag)}')
        # 返回 CEC-MAC 和 密文
        return tag, data

    def decrypt(self, tag: bytes, data: bytes, nonce: bytes) -> bytes:
        """解密数据

        Args:
            tag (bytes): CEC-MAC
            data (bytes): 密文
            nonce (bytes): 加密时使用的随机数

        Returns:
            bytes: 明文
        """
        assert len(data) > 0
        assert len(nonce) == Common.AES_CCM_NONCE_SIZE

        self.logger.debug(f'Tag: {hexlify(tag)}')
        self.logger.debug(f'Ciphertext: {hexlify(data)}')
        # 执行解密
        cipher = AES.new(self.key, mode=AES.MODE_CCM, nonce=nonce, mac_len=Common.AES_CCM_TAG_SIZE)
        data = cipher.decrypt_and_verify(data, tag)
        self.logger.debug(f'Plaintext: {hexlify(data)}')
        # 返回明文
        return data

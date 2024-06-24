from Cryptodome.Cipher import AES
from logging import Logger

from pyHost.Logging import hexlify


# AES 密钥长度 (字节)
AES_CCM_KEY_SIZE = 32
# AES CEC-MAC 长度 (字节)
AES_CCM_TAG_SIZE = 16
# AES 随机数长度 (字节)
AES_CCM_NONCE_SIZE = 12


class Cipher:
    def __init__(self, logger: Logger, key: bytes):
        """创建加密器

        Args:
            logger (Logger): 日志记录器
            key (bytes): 密钥
        """
        assert (size := len(key)) == AES_CCM_KEY_SIZE, f'Key size not match! Expect: {AES_CCM_KEY_SIZE}, Actual: {size}'

        self.logger = logger.getChild('Cipher')
        self.key = key
        self._nonce = None

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @nonce.setter
    def nonce(self, value: bytes) -> None:
        assert (size := len(value)) == AES_CCM_NONCE_SIZE, \
            f'Nonce size not match! Expect {AES_CCM_NONCE_SIZE}, Actual: {size}'
        self._nonce = value

    def encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        """加密数据

        Args:
            data (bytes): 明文

        Returns:
            tuple[bytes, bytes]: CEC-MAC, 密文
        """
        assert len(data) > 0, 'Could not encrypt empty data!'

        # 执行加密
        self.logger.debug(f'Plaintext: {hexlify(data)}')
        cipher = AES.new(self.key, mode=AES.MODE_CCM, nonce=self.nonce, mac_len=AES_CCM_TAG_SIZE)
        data, tag = cipher.encrypt_and_digest(data)
        self.logger.debug(f'Ciphertext: {hexlify(data)}')
        self.logger.debug(f'Tag: {hexlify(tag)}')
        # 返回 CEC-MAC 和 密文
        return tag, data

    def decrypt(self, tag: bytes, data: bytes) -> bytes:
        """解密数据

        Args:
            tag (bytes): CEC-MAC
            data (bytes): 密文

        Returns:
            bytes: 明文
        """
        assert len(data) > 0, 'Could not decrypt empty data!'
        assert (size := len(tag)) == AES_CCM_TAG_SIZE, \
            f'Tag size not match! Expect {AES_CCM_TAG_SIZE}, Actual: {size}'

        self.logger.debug(f'Tag: {hexlify(tag)}')
        self.logger.debug(f'Ciphertext: {hexlify(data)}')
        # 执行解密
        cipher = AES.new(self.key, mode=AES.MODE_CCM, nonce=self.nonce, mac_len=AES_CCM_TAG_SIZE)
        data = cipher.decrypt_and_verify(data, tag)
        self.logger.debug(f'Plaintext: {hexlify(data)}')
        # 返回明文
        return data

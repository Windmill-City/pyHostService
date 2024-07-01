import crcmod
import asyncio
import numpy as np
from serial import Serial
from logging import Logger

from PySide6.QtCore import *
from PySide6.QtWidgets import *

from pyHost.Logging import hexlify
from pyHost.Cipher import AES_CCM_TAG_SIZE

# 最大未处理帧数量
UNHANDLED_FRAME_SIZE_MAX = 128

# 帧头
Header = np.dtype({
    'names': ['address', 'cmd', 'size', 'error'],
    'formats': ['u1', 'u1', 'u2', 'u1']
})

# 校验算法
crc16 = crcmod.predefined.mkCrcFun('crc-ccitt-false')


class Port(QObject):
    # 已创建的端口
    Ports = dict()
    # 断联信号
    aboutToClose = Signal()

    def __init__(self, logger: Logger, serial: Serial):
        """通信端口

        Args:
            logger (Logger): 日志记录器
            serial (Serial): 串口
        """
        super().__init__()
        self._logger = logger.getChild('Port')
        self._serial = serial
        self._unhandled_frames = list()
        self._ref = 1  # 端口引用计数
        self._closed = False
        Port.Ports[self._serial.name] = self
        self._logger.info(f'[{self._serial.name}] has created!')

    def send(self, address: np.uint8, cmd: np.uint8, tag: bytes | None, extra: bytes) -> None:
        """发送数据帧

        Args:
            address (np.uint8): Server 地址
            cmd (np.uint8): 命令
            tag (bytes | None): CEC-MAC
            extra (bytes): 附加参数
        """
        # 使用 MSB 标识是否加密
        cmd = cmd if not tag else cmd | 0x80
        # 请求结构体
        head = np.array([(address, cmd, len(extra), 0)], dtype=Header)

        # 帧头校验
        checksum = np.uint16(crc16(head)).byteswap().tobytes()
        # 发送帧头
        self._write(head)
        self._write(checksum)
        self._logger.debug(f'Tx: Header: {hexlify(head)}, Checksum: {hexlify(checksum)}')

        # 数据长度为 0 则跳过发送
        if len(extra) == 0:
            return

        # 拼接 CEC-MAC
        if tag:
            extra = tag + extra

        # 参数校验
        checksum = np.uint16(crc16(extra)).byteswap().tobytes()
        # 发送参数
        self._write(extra)
        self._write(checksum)
        self._logger.debug(f'Tx: Extra[{len(extra)}]: {hexlify(extra)}, Checksum: {hexlify(checksum)}')

    async def recv(self, address: np.uint8) -> tuple[np.uint8, np.uint8, bytes | None, bytes]:
        """接收数据帧

        Args:
            address (np.uint8): Client 地址

        Returns:
            tuple[np.uint8, np.uint8, bytes, bytes]: 命令, 错误码, CEC-MAC, 附加参数
        """
        # 优先返回未处理的帧
        for item in self._unhandled_frames:
            _address, cmd, error, tag, extra = item
            if _address == address:
                self._unhandled_frames.remove(item)
                return cmd, error, tag, extra

        while True:
            # 帧同步
            head = await self._sync()
            # 数据是否加密
            encrypted = head['cmd'] & 0x80 and head['size'] > 0
            # 去除加密标记
            head['cmd'] &= 0x7F
            # 附加数据长度
            size = head['size']

            tag = None
            extra = bytes()
            # 数据不为空才继续读取
            if size > 0:
                # 接收 CEC-MAC
                if encrypted:
                    tag = bytearray(AES_CCM_TAG_SIZE)
                    for i in range(len(tag)):
                        tag[i] = await self._read()
                # 接收数据
                extra = bytearray(size)
                for i in range(len(extra)):
                    extra[i] = await self._read()
                # 接收校验和
                checksum = bytearray(2)  # sizeof(Checksum) = 2
                for i in range(len(checksum)):
                    checksum[i] = await self._read()

                # 检验数据
                if encrypted:
                    if crc16(tag+extra+checksum) != 0:
                        self._logger.warning(f'Checksum failed for an encrypted frame -> {head["cmd"]}')
                        continue
                else:
                    if crc16(extra+checksum) != 0:
                        self._logger.warning(f'Checksum failed for a unencrypted frame -> {head["cmd"]}')
                        continue

            # 返回数据
            if head['address'] == address:
                return head['cmd'], head['error'], tag, extra
            else:
                data = head['address'], head['cmd'], head['error'], tag, extra
                self._unhandled_frames.append(data)
                # 限制未处理的帧的数量
                if len(self._unhandled_frames) > UNHANDLED_FRAME_SIZE_MAX:
                    self._unhandled_frames.pop(0)
                continue

    def close(self) -> None:
        """关闭端口
        """
        if self._ref > 0:
            self._ref -= 1
        if self._ref == 0 and not self._closed:
            try:
                self._serial.flush()
            except IOError:
                pass
            self._close()

    def _close(self) -> None:
        self._closed = True
        self._serial.close()
        del Port.Ports[self._serial.name]
        self._logger.info(f'[{self._serial.name}] has closed!')
        self.aboutToClose.emit()

    async def _read(self) -> int:
        if self._closed:
            raise IOError(f'[{self._serial.name}] has closed!')
        try:
            while True:
                byte = self._serial.read()
                if len(byte) == 1:
                    return byte[0]
                else:
                    await asyncio.sleep(0)
        except IOError:
            self._close()
            raise

    def _write(self, buffer: bytes) -> None:
        if self._closed:
            raise IOError(f'[{self._serial.name}] has closed!')
        try:
            self._serial.write(buffer)
        except IOError:
            self._close()
            raise

    async def _sync(self) -> np.ndarray:
        """帧同步

        Returns:
            np.ndarray: 帧头
        """
        head = bytearray(Header.itemsize + 2)  # sizeof(Checksum) = 2
        # 帧同步
        while True:
            # 弹出左端数据
            head.pop(0)
            # 在右侧插入新数据
            head.append(await self._read())
            # 检查校验和
            if crc16(head) == 0:
                return np.frombuffer(head[0:Header.itemsize], dtype=Header)[0]

    @classmethod
    def create(cls, logger: Logger, name: str, baudrate: int):
        """创建通信端口

        Args:
            logger (Logger): 日志
            name (str): 端口名
            baudrate (int): 波特率

        Returns:
            Port: 通信端口实例
        """
        # 优先返回已有的实例
        port: Port = Port.Ports.get(name, None)
        if port is not None:
            port._ref += 1
            return port
        # 创建端口
        serial = Serial(name, baudrate=baudrate, timeout=0)
        port = Port(logger, serial)
        return port

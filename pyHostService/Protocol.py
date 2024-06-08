import crcmod
import asyncio
import numpy as np
from serial_asyncio import create_serial_connection, SerialTransport
from logging import Logger

from pyHostService.Logging import hexlify
from pyHostService import Common

# 最大未处理帧数量
UNHANDLED_FRAME_SIZE_MAX = 128

# 帧头
Header = np.dtype({
    'names': ['address', 'cmd', 'size', 'error'],
    'formats': ['u1', 'u1', 'u2', 'u1']
})

# 校验算法
crc16 = crcmod.predefined.mkCrcFun('crc-ccitt-false')


class Port(asyncio.Protocol):
    # 已创建的端口
    Ports = dict()

    async def send(self, address: np.uint8, cmd: np.uint8, tag: bytes | None, extra: bytes) -> None:
        """发送数据帧

        Args:
            address (np.uint8): Server 地址
            cmd (np.uint8): 命令
            tag (bytes | None): CEC-MAC
            extra (bytes): 附加参数
        """
        async with self.get_lock():
            # 检查端口是否正常
            if self.is_closed():
                raise IOError('Port closed!')
            # 使用 MSB 标识是否加密
            cmd = cmd if not tag else cmd | 0x80
            # 请求结构体
            head = np.array([(address, cmd, len(extra), 0)], dtype=Header)

            # 帧头校验
            checksum = np.uint16(crc16(head)).byteswap().tobytes()
            # 发送帧头
            self._transport.write(head)
            self._transport.write(checksum)
            self._logger.debug(f'Header: {hexlify(head)}, Checksum: {hexlify(checksum)}')

            # 数据长度为 0 则跳过发送
            if len(extra) == 0:
                return

            # 拼接 CEC-MAC
            if tag:
                extra = tag + extra

            # 参数校验
            checksum = np.uint16(crc16(extra)).byteswap().tobytes()
            # 发送参数
            self._transport.write(extra)
            self._transport.write(checksum)
            self._logger.debug(f'Extra: {hexlify(extra)}, Checksum: {hexlify(checksum)}')

    async def recv(self, address: np.uint8) -> tuple[np.uint8, np.uint8, bytes | None, bytes]:
        """接收数据帧

        Args:
            address (np.uint8): Client 地址

        Returns:
            tuple[np.uint8, np.uint8, bytes, bytes]: 命令, 错误码, CEC-MAC, 附加参数
        """
        async with self.get_lock():
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
                        tag = bytearray(Common.AES_CCM_TAG_SIZE)
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

    async def close(self) -> None:
        """关闭端口
        """
        async with self.get_lock():
            if self._ref > 0:
                self._ref -= 1
            if self._ref == 0:
                if not self._closed:
                    self._transport.close()
                    await self._lost

    def is_closed(self) -> bool:
        """返回端口是否关闭

        Returns:
            bool: 是否关闭
        """
        return self._closed

    def get_lock(self) -> asyncio.Lock:
        """返回端口互斥锁

        Returns:
            asyncio.Lock: 互斥锁
        """
        return self._lock

    def __init__(self, logger: Logger, port: str, loop: asyncio.AbstractEventLoop):
        """通信协议实现

        Args:
            logger (Logger): 日志记录器
            port (str): 端口名
            loop (asyncio.AbstractEventLoop): 事件循环
        """
        self._logger = logger.getChild('Protocol')
        self._port = port
        self._buffer = bytearray()
        self._unhandled_frames = list()
        self._lock = asyncio.Lock()

        self._made = loop.create_future()  # 连接建立指示
        self._lost = loop.create_future()  # 连接终止指示

        self._closed = False
        self._ref = 1  # 端口的引用数

    def connection_made(self, transport) -> None:
        self._transport: SerialTransport = transport
        self._transport.pause_reading()
        Port.Ports[self._port] = self
        self._logger.info('Port Opened!')
        self._made.set_result(True)

    def connection_lost(self, _: Exception | None) -> None:
        self._logger.info('Port Closed!')
        self._closed = True
        del Port.Ports[self._port]
        self._lost.set_result(True)

    def data_received(self, data: bytes) -> None:
        self._buffer.extend(data)
        self._transport.pause_reading()
        self._rx.set_result(True)

    async def _read(self) -> int:
        """接收 1 字节数据

        Returns:
            int: 1 字节数据
        """
        # 检查端口是否正常
        if self.is_closed():
            raise IOError('Port closed!')
        if len(self._buffer) == 0:
            loop = asyncio.get_event_loop()
            self._rx = loop.create_future()
            self._transport.resume_reading()
            await self._rx
        return self._buffer.pop(0)

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


async def create_port(logger: Logger, serial_port: str, baudrate=115200) -> Port:
    """创建通信端口

    Args:
        logger (Logger): 日志记录器
        serial_port (str): 端口名

    Returns:
        Protocol: 通信端口实例
    """
    def exception_handler(_, context: dict):
        port = context.get('protocol', None)
        if isinstance(port, Port):
            logger.error(f'Port closed due to {context["exception"]}')
        else:
            raise context['exception']

    # 优先返回已有的实例
    port = Port.Ports.get(serial_port, None)
    if port is not None:
        port._ref += 1
        return port
    # 创建新实例
    loop = asyncio.get_event_loop()
    # 处理端口关闭的异常
    loop.set_exception_handler(exception_handler)
    # 创建端口
    port = Port(logger, serial_port, loop)
    await create_serial_connection(loop, lambda: port, serial_port, baudrate=baudrate)
    # 等待端口建立
    await port._made
    return port

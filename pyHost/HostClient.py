import asyncio
from logging import Logger
import numpy as np
from typing import AsyncGenerator

from pyHost.Logging import hexlify, MaskableLogger
from pyHost.Cipher import Cipher
from pyHost import Protocol
from pyHost.Types import Command, ErrorCode, MemoryAccess, RangeAccess, LogLevel


class ServerLogger:
    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    def log(self, extra: bytes) -> None:
        if len(extra) == 0:
            self._logger.warning(f'Empty log data!')
            return
        # 日志等级
        level = extra[0:1][0]
        try:
            level = LogLevel(level)
        except ValueError:
            self._logger.warning(f'Invalid log level: {level}!')
            return
        # 日志内容
        log = extra[1:]
        log = str(log, encoding='utf-8')
        match level:
            case LogLevel.VERBOSE:
                self._logger.debug(log)
            case LogLevel.DEBUG:
                self._logger.debug(log)
            case LogLevel.INFO:
                self._logger.info(log)
            case LogLevel.WARNING:
                self._logger.warning(log)
            case LogLevel.ERROR:
                self._logger.error(log)


class Client:
    def __init__(self, logger: MaskableLogger, address: np.uint8, cipher: Cipher):
        assert isinstance(logger, MaskableLogger), f'Unsupported logger: {type(logger)}; Use MaskableLogger!'

        self._logger = logger
        self._client = logger.getChild(f'Client[{address:x}]')
        self._server = logger.getChild(f'Server[{address:x}]')
        self._server = ServerLogger(self._server)

        self._address = address

        self._symbols: dict[str, np.uint16] = None

        self._cipher = cipher

        self._block_size = 1024
        self._extra_size = 1024 + 2 + MemoryAccess.itemsize  # sizeof(PropertyId) = 2

        self._port = None

    def open(self, name: str, baudrate: int) -> None:
        """打开端口

        Args:
            name (str): 端口名
            baudrate (int): 波特率
        """
        def _cleanup():
            self._port = None
        # 销毁旧端口
        self.close()
        # 创建新端口
        self._port = Protocol.create_port(self._logger, name, baudrate)
        self._port.aboutToClose.connect(_cleanup)

    def close(self) -> None:
        """关闭通信端口
        """
        self._port: Protocol.Port
        if self._port is not None:
            self._port.close()
            self._port = None

    @property
    def opened(self) -> bool:
        return self._port is not None

    @property
    def port(self) -> Protocol.Port:
        return self._port

    async def send_request(self, cmd: Command, extra: bytes, encrypt: bool = False) -> None:
        """发送请求

        Args:
            cmd (Command): 请求命令
            extra (bytes): 附加参数
            encrypt (bool, optional): 是否加密. 默认值: False.
        """
        # 检查端口是否已经开启
        if not self.opened:
            raise RuntimeError('Port not open!')
        # 检查数据是否超过最大帧长
        if len(extra) > self._extra_size:
            raise ValueError(f'Extra of size [{len(extra)}] exceed max frame size [{self._extra_size}]!')

        tag = None
        if encrypt:
            assert len(extra) > 0, f'Could not send empty encrypt frame!'
            # 更新 Nonce
            await self._get_nonce()
            # 加密数据
            tag, extra = self._cipher.encrypt(extra)
        # 发送数据帧
        self._port.send(self._address, cmd.value, tag, extra)

    async def recv_response(self, expect: Command) -> bytes:
        """接收响应

        Args:
            expect (Command): 响应的命令

        Raises:
            ValueError: 命令执行失败 或 解密失败

        Returns:
            bytes: 附加参数
        """
        # 检查端口是否已经开启
        if not self.opened:
            raise RuntimeError('Port not open!')
        while True:
            # 接收数据帧
            cmd, error, tag, extra = await self._port.recv(self._address)
            # 转义信息
            cmd = Command(cmd)
            error = ErrorCode(error)
            self._client.debug(f'Response of {cmd} with {error}')
            # 解密数据
            if tag is not None:
                extra = self._cipher.decrypt(tag, extra)
            self._client.debug(f'Extra: {hexlify(extra)}')
            # 如果出现异常则抛出
            if error != ErrorCode.S_OK:
                raise ValueError(error)
            # 如果是目标的响应则返回
            if cmd == expect:
                return extra
            elif cmd == Command.LOG:
                # 打印服务端日志
                self._server.log(extra)
            else:
                self._client.warning(f'Unexpected response of {cmd}, expect: {expect}')

    async def connect(self, timeout=5) -> None:
        """测试连通性
        """
        self._client.info('Connecting...')
        while timeout > 0:
            try:
                async with asyncio.timeout(0.05):
                    await self.echo()
                    self._client.info('Connected!')
                    return
            except TimeoutError:
                timeout -= 0.05
        raise TimeoutError('Connect timeout!')

    async def echo(self, value: bytes = bytes(), encrypt: bool = False) -> bytes:
        """发送回声探测

        Args:
            value (bytes): 附加参数. 默认值: bytes()
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            bytes: 回应
        """
        self._client.info(f'Echo: {hexlify(value)}')
        await self.send_request(Command.ECHO, value, encrypt)
        rep = await self.recv_response(Command.ECHO)
        self._client.info(f'Echo answer: {hexlify(rep)}')
        return rep

    async def set_range(self, name: str, min: np.number, max: np.number, encrypt=False) -> None:
        """设置范围属性

        Args:
            name (str): 符号名
            min (np.number): 下限
            max (np.number): 上限
            encrypt (bool, optional): 是否加密. Defaults to False.

        Raises:
            RuntimeError: 类型不兼容
        """
        # 数据类型转换
        if not isinstance(min, np.number) or not isinstance(max, np.number):
            raise RuntimeError(f'Incompatible value type: {type(min)},{type(max)}')
        self.set_prop(name,
                      np.uint8(RangeAccess.Range.value).tobytes()
                      + min.tobytes()
                      + max.tobytes(),
                      encrypt)

    async def get_range(self, name: str, access: RangeAccess, dtype: np.dtype, encrypt=False) -> tuple[np.number, np.number]:
        """获取范围属性

        Args:
            name (str): 符号名
            dtype (np.dtype): 数值类型
            encrypt (bool, optional): 是否加密. Defaults to False.

        Returns:
            tuple[np.number, np.number]: 下限, 上限
        """
        id = self._get_id(name)
        extra = self._get_prop(id, encrypt, np.uint8(access.value).tobytes())
        return np.frombuffer(extra, dtype=[dtype, dtype])[0]

    async def set_prop(self, name: str, value: bytes, encrypt: bool = False, no_response=False) -> None:
        """设置属性值

        Args:
            name (str): 符号名
            value (bytes): 属性值
            encrypt (bool, optional): 是否加密. 默认值: False.
            no_response (bool, optional): 是否无响应. 默认值: False.
        """
        # 数据类型转换
        if isinstance(value, bool):
            value = np.uint8(value)
        elif isinstance(value, np.ndarray):
            value = value.tobytes()
        elif not isinstance(value, (bytes, bytearray)):
            raise RuntimeError(f'Incompatible value type: {type(value)}')

        self._client.info(f'Request: Set Prop[{name}]')
        # 获取属性 Id
        id = await self._get_id(name)
        # 设置属性值
        if no_response:
            await self._set_prop_no_response(id, value, encrypt)
        else:
            await self._set_prop(id, value, encrypt)
        self._client.info(f'End Request: Set Prop[{name}]')

    async def get_prop(self, name: str, encrypt: bool = False) -> bytes:
        """获取属性值

        Args:
            name (str): 符号名
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            bytes: 属性值
        """
        self._client.info(f'Request: Get Prop[{name}]')
        # 获取属性 Id
        id = await self._get_id(name)
        # 获取属性值
        extra = self._get_prop(id, encrypt)
        self._client.info(f'End Request: Get Prop[{name}]')
        return extra

    async def _get_block(self, id: np.uint16, access: np.ndarray, encrypt=False) -> bytes:
        self._client.debug(f'Get Block with offset: {access["offset"]}, size: {access["size"]}')
        # 添加参数
        extra = id.tobytes()
        extra += access
        # 发送请求
        await self.send_request(Command.GET_PROPERTY, extra, encrypt)
        # 接收响应
        extra = await self.recv_response(Command.GET_PROPERTY)
        # 自增偏移
        access['offset'] += access['size']
        # 返回获取的内容
        return extra

    async def get_mem(self, name: str, offset: np.uint16, size: np.uint16, encrypt: bool = False) -> AsyncGenerator[bytes, None]:
        """读取内存(异步生成器)

        Args:
            name (str): 符号名
            offset (np.uint16): 偏移
            size (np.uint16): 需要读取的长度
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            AsyncGenerator[bytes, None]: [单块数据, None]
        """
        self._client.info(f'Request: Get Memory[{name}]')
        # 获取 Id
        id = await self._get_id(name)
        # 已获取数据的长度
        _acquired = 0
        # MemoryAccess
        access = np.zeros(1, dtype=MemoryAccess)[0]
        access['size'] = self._block_size
        access['offset'] = offset
        # 整数倍部分
        for _ in range(int(size / access['size'])):
            _acquired += access['size']
            yield await self._get_block(id, access, encrypt)
        # 余下部分
        access['size'] = size - _acquired
        if access['size'] > 0:
            yield await self._get_block(id, access, encrypt)
        self._client.info(f'End Request: Get Memory[{name}]')

    async def _set_block(self, id: np.uint16, access: np.ndarray, data: bytes, encrypt=False) -> None:
        self._client.debug(f'Set Block with offset: {access["offset"]}, size: {access["size"]}')
        # 添加参数
        extra = bytearray()
        extra.extend(id.tobytes())
        extra.extend(access)
        extra.extend(data)
        # 发送请求
        await self.send_request(Command.SET_PROPERTY, extra, encrypt)
        # 接收响应
        await self.recv_response(Command.SET_PROPERTY)
        # 自增偏移
        access['offset'] += access['size']

    async def set_mem(self, name: str, offset: np.uint16, value: bytes, encrypt: bool = False) -> AsyncGenerator[np.uint16, None]:
        """写入内存

        Args:
            name (str): 符号名
            offset (np.uint16): 偏移
            value (bytes): 内存数据
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            AsyncGenerator[np.uint16, None]: [单块数据长度, None]
        """
        # 数据类型转换
        if isinstance(value, np.ndarray):
            value = value.tobytes()
        elif not isinstance(value, (bytes, bytearray)):
            raise RuntimeError(f'Incompatible value type: {type(value)}')

        self._client.info(f'Request: Set Memory[{name}]')
        # 数据长度
        size = len(value)
        # 获取 Id
        id = await self._get_id(name)
        # value 的偏移
        _offset = 0
        # MemoryAccess
        access = np.zeros(1, dtype=MemoryAccess)[0]
        access['size'] = self._block_size
        access['offset'] = offset
        # 整数倍部分
        for _ in range(int(size / access['size'])):
            await self._set_block(id, access, value[_offset, _offset+access['size']], encrypt)
            _offset += access['size']
            yield access['size']
        # 余下部分
        access['size'] = size - _offset
        if access['size'] > 0:
            await self._set_block(id, access, value[_offset, _offset+access['size']], encrypt)
            yield access['size']
        # 返回获取的值
        self._client.info(f'End Request: Set Memory[{name}]')

    async def get_size(self, name: str, encrypt: bool = False) -> np.uint16:
        """获取属性/内存/数组长度

        Args:
            name (str): 符号名
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            np.uint16: 长度
        """
        self._client.info(f'Request: Get Size[{name}]')
        # 获取属性 Id
        id = await self._get_id(name)
        # 获取 Id
        size = await self._get_size(id, encrypt)
        self._client.info(f'End Request: Get Size[{name}]')
        return size

    async def replace_key(self, name: str, key: bytes) -> None:
        """替换密钥

        Args:
            name (str): 符号名
            key (bytes): 新密钥
        """
        try:
            self.mask()
            await self.set_prop(name, key, encrypt=True)
            self._cipher = Cipher(self._client, key)
        finally:
            self.unmask()

    def mask(self) -> None:
        """屏蔽日志输出
        """
        self._logger.mask()

    def unmask(self) -> None:
        """恢复日志输出
        """
        self._logger.unmask()

    async def get_symbols(self) -> AsyncGenerator[str, np.uint16]:
        """获取符号表

        Returns:
            AsyncGenerator[str, np.uint16]: [符号名, 属性 Id]
        """
        self._client.debug('Request: Get Symbols')
        # 获取符号个数, symbols 的属性 id = 0
        size = await self._get_size(0)
        self._client.debug(f'symbols size: {size}')

        self._symbols = {}
        for i in range(size):
            extra = None
            try:
                # 附加参数为目标属性的 id
                extra = await self._get_prop(0, extra=np.uint16(i).tobytes())
            except ValueError:
                # 访问的变量需要权限
                try:
                    extra = await self._get_prop(0, encrypt=True, extra=np.uint16(i).tobytes())
                except ValueError:
                    self._client.warning(f'Id: {i} failed to fetch symbol')
                    continue
            name = str(extra, encoding='utf-8')
            self._symbols[name] = np.uint16(i)
            yield name, self._symbols[name]
        self._client.debug(f'Symbols: {self._symbols}')
        self._client.debug('End Request: Get Symbols')

    async def _get_id(self, name: str) -> np.uint16:
        """获取属性 Id

        Args:
            name (str): 符号名

        Returns:
            np.uint16: 属性 Id
        """
        if self._symbols is None:
            async for _ in self.get_symbols():
                pass
        return self._symbols[name]

    async def _get_nonce(self) -> bytes:
        """获取随机数

        Returns:
            bytes: 随机数
        """
        id = await self._get_id('nonce')
        self._cipher.nonce = await self._get_prop(id)
        self._client.debug(f'Nonce: {hexlify(self._cipher.nonce)}')
        return self._cipher.nonce

    async def _get_prop(self, id: np.uint16, encrypt: bool = False, extra: bytes = bytes()) -> bytes:
        await self.send_request(Command.GET_PROPERTY, np.uint16(id).tobytes() + extra, encrypt)
        extra = await self.recv_response(Command.GET_PROPERTY)
        return extra

    async def _set_prop(self, id: np.uint16, extra: bytes, encrypt: bool = False) -> None:
        await self.send_request(Command.SET_PROPERTY, np.uint16(id).tobytes() + extra, encrypt)
        await self.recv_response(Command.SET_PROPERTY)

    async def _set_prop_no_response(self, id: np.uint16, extra: bytes, encrypt: bool = False) -> None:
        await self.send_request(Command.SET_PROPERTY, np.uint16(id).tobytes() + extra, encrypt)

    async def _get_size(self, id: np.uint16, encrypt: bool = False,) -> np.uint16:
        await self.send_request(Command.GET_SIZE, np.uint16(id).tobytes(), encrypt)
        extra = await self.recv_response(Command.GET_SIZE)
        return np.frombuffer(extra, dtype=np.uint16)[0]

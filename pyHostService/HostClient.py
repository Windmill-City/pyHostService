import numpy as np
from typing import AsyncGenerator
from logging import Logger
from asyncio import Lock

from .Logging import hexlify, LogMask
from .Cipher import Cipher
from . import Protocol
from .Common import Command, ErrorCode, MemoryAccess


class Client:
    def __init__(self, logger: Logger, serial_port: str, address: np.uint8,  key: bytes, block_size=256, baudrate=115200):
        self._logger = logger
        self._lock = Lock()
        self._client = logger.getChild(f'Client[{address:x}]')
        self._server = logger.getChild(f'Server[{address:x}]')

        self._log_mask = LogMask()
        self._client.addFilter(self._log_mask)

        self._serial_port = serial_port
        self._baudrate = baudrate
        self._port = None

        self._address = address

        self._symbols: dict[str, np.uint16] = None

        self._key = key
        self._nonce: bytes = None
        self._cipher = Cipher(self._client, self._key)

        self._block_size = block_size
        self._extra_size = block_size + 2 + MemoryAccess.itemsize  # sizeof(PropertyId) = 2

    async def open(self) -> None:
        """打开连接
        """
        if self.is_opened():
            raise RuntimeError('Port already opened!')
        self._port = await Protocol.create_port(self._logger, self._serial_port, self._baudrate)

    async def close(self) -> None:
        """关闭连接
        """
        # 检查端口是否已经开启
        if not self.is_opened():
            raise RuntimeError('Port not open!')
        await self._port.close()
        self._port = None

    def is_opened(self) -> bool:
        """返回连接是否打开

        Returns:
            bool: 是否打开
        """
        return self._port is not None

    def get_lock(self) -> Lock:
        """返回互斥锁

        Returns:
            Lock: 互斥锁
        """
        return self._lock

    async def send_request(self, cmd: Command, extra: bytes, encrypt: bool = False) -> None:
        """发送请求

        Args:
            cmd (Command): 请求命令
            extra (bytes): 附加参数
            encrypt (bool, optional): 是否加密. 默认值: False.
            key (bytes, optional): 密钥. 默认值: None.
        """
        # 检查端口是否已经开启
        if not self.is_opened():
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
            tag, extra = self._cipher.encrypt(extra, self._nonce)
        try:
            # 发送数据帧
            await self._port.send(self._address, cmd.value, tag, extra)
        except IOError:
            self._client.error('Port closed unexpectedly!')
            await self.close()
            raise

    async def recv_response(self, expect: Command) -> bytes:
        """接收响应

        Args:
            expect (Command): 响应的命令
            key (bytes, optional): 密钥. 默认值: None.

        Raises:
            ValueError: 命令执行失败 或 解密失败

        Returns:
            bytes: 附加参数
        """
        # 检查端口是否已经开启
        if not self.is_opened():
            raise RuntimeError('Port not open!')
        while True:
            try:
                # 接收数据帧
                cmd, error, tag, extra = await self._port.recv(self._address)
            except IOError:
                self._client.error('Port closed unexpectedly!')
                await self.close()
                raise
            # 转义信息
            cmd = Command(cmd)
            error = ErrorCode(error)
            self._client.debug(f'Response of {cmd} with {error}')
            # 解密数据
            if tag is not None:
                extra = self._cipher.decrypt(tag, extra, self._nonce)
            self._client.debug(f'Extra: {hexlify(extra)}')
            # 如果出现异常则抛出
            if error != ErrorCode.S_OK:
                raise ValueError(error)
            # 如果是目标的响应则返回
            if cmd == expect:
                return extra
            elif cmd == Command.LOG:
                # 打印服务端日志
                self._server.info(f'{hexlify(extra)}')
            else:
                self._client.warning(f'Unexpected response of {cmd}, expect: {expect}')

    async def echo(self, value: bytes = bytes(), encrypt: bool = False) -> bytes:
        """发送回声探测

        Args:
            value (bytes): 附加参数. 默认值: bytes()
            encrypt (bool, optional): 是否加密. 默认值: False.
            key (bytes, optional): 密钥. 默认值: None.

        Returns:
            bytes: 回应的附加参数
        """
        async with self.get_lock():
            self._client.info(f'Echo with {hexlify(value)}')
            await self.send_request(Command.ECHO, value, encrypt)
            rep = await self.recv_response(Command.ECHO)
            self._client.info(f'Echo answer with {hexlify(rep)}')
            return rep

    async def get_prop(self, name: str, encrypt: bool = False) -> bytes:
        """读取属性

        Args:
            name (str): 符号名
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            bytes: 属性值
        """
        async with self.get_lock():
            self._client.info(f'Request: Get Property[{name}]')
            extra = self._get_prop(name, encrypt)
            self._client.info(f'End Request: Get Property[{name}]')
            return extra

    async def set_prop(self, name: str, value: bytes,  encrypt: bool = False, no_response: bool = False) -> bytes:
        """设置属性

        Args:
            name (str): 符号名
            value (bytes): 属性值
            encrypt (bool, optional): 是否加密. 默认值: False.
            no_response (bool, optional): 是否不接收响应. 默认值: False.

        Returns:
            bytes: 响应的附加参数
        """
        # 数据类型转换
        if isinstance(value, bool):
            value = np.uint8(value).tobytes()
        elif isinstance(value, (np.ndarray, np.number)):
            value = value.tobytes()
        elif not isinstance(value, (bytes, bytearray)):
            self._client.warning(f'Possible incompatible value type: {type(value)}')

        async with self.get_lock():
            self._client.info(f'Request: Set Property[{name}] with {hexlify(value)}')
            # 获取 Id
            id = await self._get_id(name)
            # 添加参数
            extra = id.tobytes() + value
            # 发送请求
            await self.send_request(Command.SET_PROPERTY, extra, encrypt)
            # 若无需接收响应则返回空数据
            if no_response:
                return bytes()
            # 接收响应
            extra = await self.recv_response(Command.SET_PROPERTY)
            self._client.info(f'End Request: Set Property[{name}]')
            return extra

    async def get_mem(self, name: str, size: np.uint16, encrypt: bool = False) -> AsyncGenerator[bytes, None]:
        """读取内存(异步生成器)

        Args:
            name (str): 符号名
            size (np.uint16): 需要读取的长度
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            AsyncGenerator[bytes, None]: [单块数据, None]
        """
        async def get_block(id: np.uint16, access: np.ndarray) -> bytes:
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

        async with self.get_lock():
            self._client.info(f'Request: Get Memory[{name}]')
            # 获取 Id
            id = await self._get_id(name)
            # MemoryAccess
            access = np.zeros(1, dtype=MemoryAccess)[0]
            # 1 block数据的最大长度
            access['size'] = self._block_size
            # 整数倍部分
            for _ in range(int(size / access['size'])):
                yield await get_block(id, access)
            # 余下部分
            access['size'] = size - access['offset']
            if access['size'] > 0:
                yield await get_block(id, access)
            self._client.info(f'End Request: Get Memory[{name}]')

    async def set_mem(self, name: str, value: bytes, encrypt: bool = False) -> AsyncGenerator[np.uint16, None]:
        """写入内存

        Args:
            name (str): 符号名
            value (bytes): 内存数据
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            AsyncGenerator[np.uint16, None]: [单块数据长度, None]
        """
        async def set_block(id: np.uint16, access: np.ndarray) -> None:
            self._client.debug(f'Set Block with offset: {access["offset"]}, size: {access["size"]}')
            # 添加参数
            extra = bytearray()
            extra.extend(id.tobytes())
            extra.extend(access)
            extra.extend(value[access['offset']:access['offset']+access['size']])
            # 发送请求
            await self.send_request(Command.SET_PROPERTY, extra, encrypt)
            # 接收响应
            await self.recv_response(Command.SET_PROPERTY)
            # 自增偏移
            access['offset'] += access['size']
        # 数据类型转换
        if isinstance(value, np.ndarray):
            value = value.tobytes()
        elif not isinstance(value, (bytes, bytearray)):
            self._client.warning(f'Possible incompatible value type: {type(value)}')

        async with self.get_lock():
            self._client.info(f'Request: Set Memory[{name}]')
            # 数据长度
            size = len(value)
            # 获取 Id
            id = await self._get_id(name)
            # MemoryAccess
            access = np.zeros(1, dtype=MemoryAccess)[0]
            # 1 block数据的最大长度
            access['size'] = self._block_size
            # 整数倍部分
            for _ in range(int(size / access['size'])):
                await set_block(id, access)
                yield access['size']
            # 余下部分
            access['size'] = size - access['offset']
            if access['size'] > 0:
                await set_block(id, access)
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
        async with self.get_lock():
            self._client.info(f'Request: Get Size[{name}]')
            # 获取属性 Id
            id = await self._get_id(name)
            # 发送请求
            await self.send_request(Command.GET_SIZE, id.tobytes(), encrypt)
            # 接收响应
            extra = await self.recv_response(Command.GET_SIZE)
            # 解析响应
            extra = np.frombuffer(extra, dtype=np.uint16)
            self._client.info(f'End Request: Get Size[{name}]')
            return extra

    async def replace_key(self, name: str, key: bytes) -> None:
        """替换密钥

        Args:
            name (str): 符号名
            key (bytes): 新密钥
        """
        try:
            self.mask()
            await self.set_prop(name, key, encrypt=True)
            self._key = key
            self._cipher = Cipher(self._client, self._key)
        finally:
            self.unmask()

    async def _get_id(self, name: str) -> np.uint16:
        """获取属性 Id

        Args:
            name (str): 符号名

        Returns:
            np.uint16: 属性 Id
        """
        if self._symbols is None:
            async for _ in self._get_symbols():
                pass
        return self._symbols[name]

    async def _get_symbols(self) -> AsyncGenerator[str, np.uint16]:
        """获取符号表

        Returns:
            AsyncGenerator[str, np.uint16]: [符号名, 属性 Id]
        """
        async def get_size() -> np.uint16:
            # symbols 属性 id为 0
            await self.send_request(Command.GET_SIZE, b'\x00\x00')
            extra = await self.recv_response(Command.GET_SIZE)
            return np.frombuffer(extra, dtype=np.uint16)[0]
        self._client.debug('Request: Get Symbols')
        # symbols 长度
        size = await get_size()
        self._client.debug(f'symbols size: {size}')

        self._symbols = {}
        for i in range(size):
            try:
                # symbols 属性 id为 0, 附加参数为 symbol 的 index
                await self.send_request(Command.GET_PROPERTY, b'\x00\x00' + i.to_bytes(2, byteorder='little'))
                extra = await self.recv_response(Command.GET_PROPERTY)
                name = str(extra, encoding='utf-8')
            except ValueError:
                # 访问的变量需要权限
                try:
                    await self.send_request(Command.GET_PROPERTY, b'\x00\x00' + i.to_bytes(2, byteorder='little'), encrypt=True)
                    extra = await self.recv_response(Command.GET_PROPERTY)
                    name = str(extra, encoding='utf-8')
                except ValueError:
                    self._client.warning(f'Id: {i} failed to fetch symbol')
                    continue
            self._symbols[name] = np.uint16(i)
            yield name, self._symbols[name]
        self._client.debug(f'Symbols: {self._symbols}')
        self._client.debug('End Request: Get Symbols')

    async def _get_nonce(self) -> bytes:
        """获取随机数

        Returns:
            bytes: 随机数
        """
        self._nonce = await self._get_prop('nonce')
        self._client.debug(f'Nonce: {hexlify(self._nonce)}')
        return self._nonce

    async def _get_prop(self, name: str, encrypt: bool = False) -> bytes:
        """读取属性(内部)

        Args:
            name (str): 符号名
            encrypt (bool, optional): 是否加密. 默认值: False.

        Returns:
            bytes: 属性值
        """
        # 获取 Id
        id = await self._get_id(name)
        # 发送请求
        await self.send_request(Command.GET_PROPERTY, id.tobytes(), encrypt)
        # 接收响应
        extra = await self.recv_response(Command.GET_PROPERTY)
        return extra

    def mask(self) -> None:
        """屏蔽日志输出
        """
        self._log_mask.mask()

    def unmask(self) -> None:
        """恢复日志输出
        """
        self._log_mask.unmask()

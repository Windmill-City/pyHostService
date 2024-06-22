import numpy as np
from enum import Enum, auto


class ErrorCode(Enum):
    S_OK = 0  # 执行成功
    E_FAIL = auto()  # 执行失败
    E_ALIGN = auto()  # 未对齐的访问
    E_TIMEOUT = auto()  # 执行超时
    E_BAD_BLOCK = auto()  # 闪存写入失败
    E_READ_ONLY = auto()  # 只读变量
    E_INVALID_ARG = auto()  # 参数有误
    E_OUT_OF_INDEX = auto()  # 内存访问越界
    E_NO_IMPLEMENT = auto()  # 方法未实现
    E_ID_NOT_EXIST = auto()  # Id不存在
    E_NO_PERMISSION = auto()  # 没有权限
    E_OUT_OF_BUFFER = auto()  # 超出帧长限制
    E_ILLEGAL_STATE = auto()  # 非法状态
    E_OVER_LOW_LIMIT = auto()  # 超出下限
    E_OVER_HIGH_LIMIT = auto()  # 超出上限


class LogLevel(Enum):
    VERBOSE = 0
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()


class RangeAccess(Enum):
    Range = 0  # 范围属性
    Absolute = auto()  # 绝对范围属性


class Access(Enum):
    READ = 0
    READ_WRITE = auto()
    WRITE_PROTECT = auto()
    READ_PROTECT = auto()
    READ_WRITE_PROTECT = auto()


class Command(Enum):
    ECHO = 0
    GET_PROPERTY = auto()
    SET_PROPERTY = auto()
    GET_SIZE = auto()
    GET_ACCESS = auto()
    LOG = auto()


# 内存访问参数
MemoryAccess = np.dtype({
    'names': ['offset', 'size'],
    'formats': ['u2', 'u2']
})

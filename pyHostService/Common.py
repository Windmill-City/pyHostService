import numpy as np
from enum import Enum

# AES 密钥长度 (字节)
AES_CCM_KEY_SIZE = 32
# AES CEC-MAC 长度 (字节)
AES_CCM_TAG_SIZE = 16
# AES 随机数长度 (字节)
AES_CCM_NONCE_SIZE = 12

# 内存访问信息
MemoryAccess = np.dtype({
    'names': ['offset', 'size'],
    'formats': ['u2', 'u2']
})


class RangeAccess(Enum):
    Range = 0     # 范围属性
    Absolute = 1  # 绝对范围属性


class Command(Enum):
    ECHO = 0
    """
    回声; 发送什么就回应什么

    请求: CMD,任意N字节数据(N>=0)
    应答:
    CMD,S_OK,请求中的附加参数
    """
    GET_PROPERTY = 1
    """
    读取属性值

    请求: CMD,属性Id
    应答:
    CMD,S_OK,属性值
    CMD,E_NO_IMPLEMENT,属性Id
    CMD,E_INVALID_ARG,属性Id
    CMD,E_ID_NOT_EXIST,属性Id
    CMD,E_NO_PERMISSION,属性Id
    CMD,E_OUT_OF_BUFFER,属性Id
    """
    SET_PROPERTY = 2
    """
    写入属性值

    请求: CMD,属性Id,属性值
    应答:
    CMD,S_OK
    CMD,E_NO_IMPLEMENT,属性Id
    CMD,E_INVALID_ARG,属性Id
    CMD,E_ID_NOT_EXIST,属性Id
    CMD,E_NO_PERMISSION,属性Id
    CMD,E_READ_ONLY,属性Id
    CMD,E_OVER_HIGH_LIMIT,属性Id
    CMD,E_OVER_LOW_LIMIT,属性Id
    CMD,E_ILLEGAL_STATE,属性Id
    """
    GET_SIZE = 3
    """
    获取属性值长度

    请求: CMD,属性Id
    应答:
    CMD,S_OK,属性长度
    CMD,E_INVALID_ARG,属性Id
    CMD,E_ID_NOT_EXIST,属性Id
    CMD,E_NO_PERMISSION,属性Id
    """
    LOG = 4
    """
    日志(仅服务端发送)

    请求: CMD,S_OK,日志数据
    应答: 无
    """


class ErrorCode(Enum):
    S_OK = 0                # 执行成功
    E_FAIL = 1              # 执行失败
    E_TIMEOUT = 2           # 执行超时
    E_NO_IMPLEMENT = 3      # 方法未实现
    E_INVALID_ARG = 4       # 参数有误
    E_ID_NOT_EXIST = 5      # Id不存在
    E_NO_PERMISSION = 6     # 没有权限
    E_OUT_OF_BUFFER = 7     # 超出帧长限制
    E_READ_ONLY = 8         # 只读变量
    E_OUT_OF_INDEX = 9      # 内存访问越界
    E_OVER_HIGH_LIMIT = 10  # 超出上限
    E_OVER_LOW_LIMIT = 11   # 超出下限
    E_ILLEGAL_STATE = 12    # 非法状态

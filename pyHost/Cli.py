from gooey import Gooey, GooeyParser

from serial.tools.list_ports import comports

import logging
import asyncio
import sys

import numpy as np

from pyHost import Client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


async def firmware(args):
    client = Client(logger, args.port, 0x80, bytes(32), block_size=args.size, baudrate=args.baudrate)
    logger.info('Waiting for Bootloader to startup...')
    # 建立连接
    await client.open()
    # 读取固件数据
    data = np.fromfile(args.firmware, dtype=np.uint8)
    # 上传固件
    uploaded = 0
    async for size in client.set_mem('flash.app', data, encrypt=True):
        uploaded += size
        print(f'progress: {uploaded/len(data) * 100:.2f}%')
        sys.stdout.flush()
    # 复位
    await client.set_prop('reset', True, no_response=True)
    # 断开连接
    await client.close()


async def waveform(args):
    client = Client(logger, args.port, 0x00, bytes(32), block_size=256, baudrate=args.baudrate)
    logger.info('Waiting for connection...')
    # 建立连接
    await client.open()
    # 读取波形数据
    data = np.fromfile(args.wave, dtype=np.uint16)
    # 上传波形
    uploaded = 0
    async for size in client.set_mem('wave.ld.0', data):
        uploaded += size
        print(f'progress: {uploaded/len(data) * 100:.2f}%')
        sys.stdout.flush()
    # 断开连接
    await client.close()


async def cli():
    parser = GooeyParser(description='Host service tool writing in Python.')
    subparser = parser.add_subparsers(required=True)

    # 固件升级
    ports = [port.name for port in comports()]

    parser_firmware = subparser.add_parser('firmware')
    parser_firmware.add_argument('firmware', help='path to the firmware', widget='FileChooser')
    parser_firmware.add_argument('--port',
                               choices=ports,
                               default=None if len(ports) == 0 else ports[0],
                               required=True,
                               help='serial port to use',
                               widget='Dropdown')
    parser_firmware.add_argument('--baudrate', type=int, default=115200,
                               choices=[9600, 115200, 1152000], help='baudrate of the serial port')
    parser_firmware.add_argument('--size', type=int, default=8192,
                               choices=[256, 1024, 2048, 4096, 8192], help='block size of one frame')
    parser_firmware.set_defaults(func=firmware)

    parser_waveform = subparser.add_parser('waveform')
    parser_waveform.add_argument('waveform', help='path to the waveform', widget='FileChooser')
    parser_waveform.add_argument('--port',
                               choices=ports,
                               default=None if len(ports) == 0 else ports[0],
                               required=True,
                               help='serial port to use',
                               widget='Dropdown')
    parser_waveform.add_argument('--baudrate', type=int, default=115200,
                               choices=[9600, 115200, 1152000], help='baudrate of the serial port')
    parser_waveform.set_defaults(func=waveform)

    args = parser.parse_args()

    await args.func(args)


@Gooey(
    target='pyhost',
    clear_before_run=True,
    progress_regex=r"progress: (\d+.\d+)%",
)
def main():
    asyncio.run(cli())


def main_cli():
    asyncio.run(cli())

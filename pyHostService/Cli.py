from gooey import Gooey, GooeyParser

from serial.tools.list_ports import comports

import logging
import asyncio
import sys

import numpy as np

from pyHostService import Client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


async def upload(args):
    async def wait_for_boot():
        logger.info('Waiting for Bootloader to startup...')
        while True:
            try:
                client.mask()
                async with asyncio.timeout(0.05):
                    await client.echo()
                    break
            except TimeoutError:
                pass
            finally:
                client.unmask()
    client = Client(logger, args.port, 0x80, bytes(32), block_size=args.size, baudrate=args.baudrate)
    # 打开串口
    await client.open()
    # 等待 Bootloader 启动
    await wait_for_boot()
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
    # 关闭串口
    await client.close()


async def cli():
    parser = GooeyParser(description='Host service tool writing in Python.')
    subparser = parser.add_subparsers(required=True)

    # 固件升级
    ports = [port.name for port in comports()]

    parser_upload = subparser.add_parser('upload')
    parser_upload.add_argument('firmware', help='path to the firmware', widget='FileChooser')
    parser_upload.add_argument('--port',
                               choices=ports,
                               default=None if len(ports) == 0 else ports[0],
                               required=True,
                               help='serial port to use',
                               widget='Dropdown')
    parser_upload.add_argument('--baudrate', type=int, default=115200,
                               choices=[9600, 115200, 1152000], help='baudrate of the serial port')
    parser_upload.add_argument('--size', type=int, default=8192,
                               choices=[256, 1024, 2048, 4096, 8192], help='block size of one frame')
    parser_upload.set_defaults(func=upload)

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

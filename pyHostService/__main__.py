from gooey import Gooey, GooeyParser

from . import Client


@Gooey
def main():
    parser = GooeyParser(description='Host service tool writing in Python.')

    # 固件升级
    subparser = parser.add_subparsers()
    upload = subparser.add_parser('upload')
    upload.add_argument('firmware', help='path to the firmware', widget='FileChooser')
    upload.add_argument('--baudrate', type=int, default=1152000,
                        choices=[9600, 115200, 1152000], help='baudrate of the serial port')
    upload.add_argument('--size', type=int, default=8192,
                        choices=[256, 1024, 2048, 4096, 8192], help='block size of one frame')
    args = parser.parse_args()

    print(args)


main()

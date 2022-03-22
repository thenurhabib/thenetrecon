#!/usr/bin python3
# -*- coding: utf-8 -*-

__Name__ = "TheNetRecon"
__Description__ = "Network Recon Tool."
__author__ = "Md. Nur Habib"
__Version__ = "1.0"


import os


__all__ = ['getTerminalSize']


def getTerminalSize():
    import platform
    current_os = platform.system()
    tuple_xy = None

    if current_os == 'Linux' or current_os == 'Darwin' or current_os.startswith('CYGWIN'):
        tuple_xy = _getTerminalSize_linux()
    if tuple_xy is None:
        print("default")
        tuple_xy = (80, 25)  # default value
    return tuple_xy


def _getTerminalSize_linux():
    def ioctl_GWINSZ(fd):
        try:
            import fcntl
            import termios
            import struct
            import os
            cr = struct.unpack('hh', fcntl.ioctl(
                fd, termios.TIOCGWINSZ, '1234'))
        except:
            return None
        return cr

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        try:
            cr = (env['LINES'], env['COLUMNS'])
        except:
            return None
    return int(cr[1]), int(cr[0])


if __name__ == "__main__":
    sizex, sizey = getTerminalSize()
    print('width =', sizex, 'height =', sizey)

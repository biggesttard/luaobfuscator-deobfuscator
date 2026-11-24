"""deobf - static LuaObfuscator deobfuscator.

Supports Chaotic Good, Chaotic Evil and Obfuscate v1 output.
"""

from __future__ import annotations

from .deobf import deobf, DeobfError, OUT_HDR, with_hdr

__version__ = '2.0.0'
__all__ = ['deobf', 'DeobfError', 'OUT_HDR', 'with_hdr', '__version__']

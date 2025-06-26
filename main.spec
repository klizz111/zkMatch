# -*- mode: python ; coding: utf-8 -*-
import os
import shutil

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('app/templates', 'app/templates'),
        ('app/static', 'app/static'),
        ('requirements.txt', '.'),
    ],
    hiddenimports=[
        'pycryptodome',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Random',
        'Crypto.Util',
        'cryptography',
        'cryptography.hazmat',
        'cryptography.x509',
        'sqlite3',
        'flask',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='matching_system',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='matching_system'
)

# 清理build文件夹
try:
    if os.path.exists('build'):
        shutil.rmtree('build')
        print("✓ Build folder cleaned successfully!")
except Exception as e:
    print(f"✗ Failed to clean build folder: {e}")
@echo off
echo ==========================================
echo    JSSecretHunter -- Windows Install
echo ==========================================
echo.
echo [*] Installing optional packages...
pip install Pillow PySocks brotli
echo.
echo [OK] Done!
echo Run: python jssecrethunter_gui.py
pause

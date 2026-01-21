@echo off
title Python Dependency Installer
echo ================================
echo Installing required Python packages
echo ================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is NOT installed.
    echo Please install Python from https://www.python.org/
    echo Make sure to check "Add Python to PATH"
    pause
    exit
)

echo ✅ Python found.
echo.

REM Upgrade pip
echo Updating pip...
python -m pip install --upgrade pip
echo.

REM Install requirements
echo Installing packages from requirements.txt...
python -m pip install -r requirements.txt
echo.

echo ================================
echo ✅ Installation complete!
echo ================================
pause

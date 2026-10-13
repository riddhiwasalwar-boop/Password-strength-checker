@echo off
title Password Strength Checker
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python is not installed or not in PATH.
    echo Download it from https://www.python.org/downloads/ and tick "Add Python to PATH".
    pause
    exit /b 1
)

:menu
cls
echo ==========================================
echo      PASSWORD STRENGTH CHECKER
echo ==========================================
echo.
echo   1. Check a password
echo   2. Check a password + online breach check
echo   3. Generate a strong password
echo   4. Exit
echo.
set "choice="
set /p choice=Enter your choice (1-4): 

if "%choice%"=="1" goto check
if "%choice%"=="2" goto online
if "%choice%"=="3" goto generate
if "%choice%"=="4" exit /b 0
echo Invalid choice.
timeout /t 2 >nul
goto menu

:check
echo.
python password_checker.py
pause
goto menu

:online
echo.
echo Note: only the first 5 characters of the password's SHA-1 hash are sent.
python password_checker.py --online
pause
goto menu

:generate
echo.
set "len=16"
set /p len=Password length (default 16): 
python password_checker.py --generate %len%
pause
goto menu

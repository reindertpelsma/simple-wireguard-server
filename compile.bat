@echo off
setlocal

if "%GOTOOLCHAIN%"=="" set "GOTOOLCHAIN=auto"

if not exist ".\uwgsocks.exe" (
    if exist ".\userspace-wireguard-socks\" (
        if not exist ".\userspace-wireguard-socks\uwgsocks.exe" (
            pushd ".\userspace-wireguard-socks"
            go build -o uwgsocks.exe .\cmd\uwgsocks
            popd
        )
        copy /Y ".\userspace-wireguard-socks\uwgsocks.exe" ".\uwgsocks.exe" >nul
    ) else (
        if exist "..\userspace-wireguard-socks\" (
            if not exist "..\userspace-wireguard-socks\uwgsocks.exe" (
                pushd "..\userspace-wireguard-socks"
                go build -o uwgsocks.exe .\cmd\uwgsocks
                popd
            )
            copy /Y "..\userspace-wireguard-socks\uwgsocks.exe" ".\uwgsocks.exe" >nul
        ) else (
            if not exist "..\uwgsocks.exe" (
                if exist "..\uwgsocks.go" (
                    pushd ".."
                    go build -o uwgsocks.exe .\cmd\uwgsocks
                    popd
                ) else (
                    echo uwgsocks not found, either clone as sub repo in this folder, put it on the parent folder, or make this a sub folder of the uwgsocks
                    echo Continuing building without uwgsocks
                )
            )
            if exist "..\uwgsocks.exe" (
                copy /Y "..\uwgsocks.exe" ".\uwgsocks.exe" >nul
            )
        )
    )
)

if exist "frontend\" (
    if exist "frontend\dist" rmdir /S /Q "frontend\dist"

    pushd "frontend"
    call npm install
    if errorlevel 1 (
        popd
        exit /b 1
    )

    call npm run build
    if errorlevel 1 (
        popd
        exit /b 1
    )
    popd

    if exist "dist" rmdir /S /Q "dist"
    mkdir "dist"

    xcopy "frontend\dist\*" "dist\" /E /I /Y >nul
) else (
    echo Source frontend dir not found. Skipping frontend build ^(hope dist exists^).
)


go build -trimpath -ldflags="-s -w" -o uwgsocks-ui.exe
if errorlevel 1 exit /b %errorlevel%

echo COMPILE SUCCEEDED. Built uwgsocks-ui.exe
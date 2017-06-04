:: ==================================================================================
:: Name:	Remove-Package.cmd
:: Author:	Nguyen Tuan
:: Website:	www.blogthuthuatwin10.com
:: Warning:	First download SetACL.exe at https://yadi.sk/d/nMQ3fi0_3JojuN and copy it path to c:\windows\system32
:: ==================================================================================

:Settings
@echo off
title Remove-Package
color 3f
cd /d %~dp0
:: ------------------------------------------------------------------------------------

:Permission
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if "%errorlevel%" NEQ "0" (
	echo: Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
	echo: UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
	"%temp%\getadmin.vbs" &	exit 
)
if exist "%temp%\getadmin.vbs" del /f /q "%temp%\getadmin.vbs"
:: ------------------------------------------------------------------------------------

:Version
cls
ver | findstr /i "10\.0\.10240"
if %ERRORLEVEL% EQU 0 (
echo.You are running Windows 10, Version 1507.
echo.Batch file only support Windows 10, Version 1703.
pause
goto Close
)
ver | findstr /i "10\.0\.10586"
if %ERRORLEVEL% EQU 0 (
echo You are running Windows 10, Version 1511.
echo.Batch file only support Windows 10, Version 1703.
pause
goto Close
)
ver | findstr /i "10\.0\.14393"
if %ERRORLEVEL% EQU 0 (
echo You are running Windows 10, Version 1607.
echo.Batch file only support Windows 10, Version 1703.
pause
goto Close
)
ver | findstr /i "10\.0\.15063"
if %ERRORLEVEL% EQU 0 (
cls
set Packages=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages
SetACL -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" -ot reg -actn setowner -ownr "n:%USERDOMAIN%\%USERNAME%"
SetACL -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" -ot reg -actn ace -ace "n:%USERDOMAIN%\%USERNAME%;p:full"
goto Menu
)
:: ------------------------------------------------------------------------------------

:Menu
cls
echo.Remove-Package Menu
echo.
echo.ID	Option			ID	Option
echo.
echo.1	Connect			19	Media Features					
echo.2	Cortana			20	Microsoft Message Queue (MSMQ) Server
echo.3	Get Help		21	Microsoft Print to PDF		
echo.4	Microsoft Edge		22	MultiPoint Connector		
echo.5	Mixed Reality Portal	23	Print and Document Services	
echo.6	OneDrive		24	RAS Connection Manager Adminitration Kit (CMAK)		
echo.7	Quick Assist		25	Remove Differential Compression API Support		
echo.8	Windows Defender	26	RIP Listener	
echo.9	Windows Spotlight	27	Services for NFS
echo.10	Windows Photo Viewer	28	Simple Network Management Protocol (SNMP)
echo.11	Snipping Tool		29	Simple TCPIP services (i.e. echo daytime etc)	
echo.12	Active Directory	30	SMB 1.0/CIFS File Sharing Support			
echo.13	Containers		31	Telnet-TFTP Client			
echo.14	Assigned Access		32	Windows Identify Foundation 3.5
echo.15	Device Lockdown		33	Windows Powershell 2.0	
echo.16	Hyper-V			34	Windows TIFF IFilter							
echo.17	Internet Explorer	35	XPS Services	
echo.18	Legacy Components	36	XPS Viewer
echo.				
		
echo.

set /p option=Select ID and press Enter: 
if %option% EQU 1 (
    call :Connect
) else if %option% EQU 2 (
    call :Cortana
) else if %option% EQU 3 (
    call :GetHelp
) else if %option% EQU 4 (
    goto MicrosoftEdge
) else if %option% EQU 5 (
    goto MixedRealityPortal
) else if %option% EQU 6 (
    goto OneDrive
) else if %option% EQU 7 (
    goto QuickAssist
) else if %option% EQU 8 (
    goto WindowsDefender
) else if %option% EQU 9 (
    goto WindowsSpotlight
) else if %option% EQU 10 (
    goto PhotoViewer
) else if %option% EQU 11 (
    goto SnippingTool
) else if %option% EQU 12 (
    goto ActiveDirectory
) else if %option% EQU 13 (
    goto Containers
) else if %option% EQU 14 (
    goto AssignedAccess
) else if %option% EQU 15 (
    goto DeviceLockdown
) else if %option% EQU 16 (
    goto Hyper-V
) else if %option% EQU 17 (
    goto InternetExplorer11
) else if %option% EQU 18 (
    goto LegacyComponents
) else if %option% EQU 19 (
    goto MediaFeatures
) else if %option% EQU 20 (
    goto MessageQueue
) else if %option% EQU 21 (
    goto PrinttoPDF
) else if %option% EQU 22 (
    goto MultiPointConnector
) else if %option% EQU 23 (
    goto PrintandDocument
) else if %option% EQU 24 (
    goto RASConnectionManager
) else if %option% EQU 25 (
    goto DifferentialCompressionAPI
) else if %option% EQU 26 (
    goto RIPListener
) else if %option% EQU 27 (
    goto ServicesforNFS
) else if %option% EQU 28 (
    goto SimpleNetwork
) else if %option% EQU 29 (
    goto SimpleTCPIP
) else if %option% EQU 30 (
    goto FileSharingSupport
) else if %option% EQU 31 (
    goto TelnetClient
) else if %option% EQU 32 (
    goto IdentifyFoundation
) else if %option% EQU 33 (
    goto Powershell2.0
) else if %option% EQU 34 (
    goto TIFFIFilter
) else if %option% EQU 35 (
    goto XPSServices
) else if %option% EQU 36 (
    goto XPSViewer
) else (
    echo.
    echo.Invalid option.
    pause
    goto Menu
)
:: ------------------------------------------------------------------------------------

:Connect
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Connect
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-Connect
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-PPIProjection-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-PPIProjection-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-PPIProjection-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-PPIProjection-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:Cortana
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Cortana
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-Cortana
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Cortana-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Cortana-PAL-Desktop-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Cortana-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /Remove-Package /packagename:Microsoft-Windows-Cortana-PAL-Desktop-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Cortana-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Cortana-PAL-Desktop-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Cortana-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /Remove-Package /packagename:Microsoft-Windows-Cortana-PAL-Desktop-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:GetHelp
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-ContactSupport
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-ContactSupport
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-ContactSupport-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-ContactSupport-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-ContactSupport-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-ContactSupport-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:MicrosoftEdge
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MicrosoftEdge
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-MicrosoftEdge
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Internet-Browser-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Internet-Browser-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Internet-Browser-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Internet-Browser-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:MixedRealityPortal
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MixedRealityPortal
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-MixedRealityPortal
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Holographic-Desktop-Analog-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Holographic-Desktop-Merged-analog-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Holographic-Desktop-Merged-onecoreuap-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Holographic-Desktop-Merged-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Holographic-Desktop-Merged-WOW64-analog-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Holographic-Desktop-Merged-WOW64-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Holographic-Desktop-Analog-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Holographic-Desktop-Merged-analog-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Holographic-Desktop-Merged-onecoreuap-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Holographic-Desktop-Merged-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Holographic-Desktop-Merged-WOW64-analog-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Holographic-Desktop-Merged-WOW64-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
) ELSE (
echo.You are running 32-bit version of Windows, Mixed Reality Portal app only support 64-bit version
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
)
:: ------------------------------------------------------------------------------------

:OneDrive
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-OneDrive
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-OneDrive
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
start /wait %systemroot%\SysWOW64\OneDriveSetup.exe /uninstall
reg delete "%Packages%\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
dism /online /remove-package /packagename:Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
start /wait %systemroot%\System32\OneDriveSetup.exe /uninstall
reg delete "%Packages%\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
dism /online /remove-package /packagename:Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:QuickAssist
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-QuickAssist
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-QuickAssist
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-QuickAssist-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-QuickAssist-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-QuickAssist-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-QuickAssist-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:WindowsDefender
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-WindowsDefender
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-WindowsDefender
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "hide:windowsdefender" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealth /f
reg delete "%Packages%\Windows-Defender-AM-Default-Definitions-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-AppLayer-Group-amcore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-AppLayer-Group-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-AppLayer-Group-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-ApplicationGuard-Inbox-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-Group-Policy-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Shield-Provider-Core-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Windows-Defender-AM-Default-Definitions-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-AppLayer-Group-amcore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-AppLayer-Group-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-AppLayer-Group-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-ApplicationGuard-Inbox-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-Group-Policy-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Shield-Provider-Core-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v SettingsPageVisibility /t REG_SZ /d "hide:windowsdefender" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v Enabled /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SecurityHealth /f
reg delete "%Packages%\Windows-Defender-AM-Default-Definitions-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-AppLayer-Group-amcore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-AppLayer-Group-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-AppLayer-Group-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-ApplicationGuard-Inbox-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Defender-Group-Policy-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Windows-Shield-Provider-Core-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Windows-Defender-AM-Default-Definitions-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-AppLayer-Group-amcore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-AppLayer-Group-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-AppLayer-Group-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-ApplicationGuard-Inbox-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Defender-Group-Policy-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Windows-Shield-Provider-Core-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
echo.How to delete the Windows Defender Security Center icon in the Start menu.
echo See details https://goo.gl/8HtNsc
start https://goo.gl/8HtNsc
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:WindowsSpotlight
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-WindowsSpotlight
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-WindowsSpotlight
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-ContentDeliveryManager-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-ContentDeliveryManager-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-ContentDeliveryManager-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-ContentDeliveryManager-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:PhotoViewer
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-PhotoViewer
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-PhotoViewer
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-PhotoBasicPackage~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-PhotoBasicPackage~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-PhotoBasicPackage~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-PhotoBasicPackage~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:SnippingTool
cls
choice /c YN /n /m "WARNING: The application can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-SnippingTool
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-SnippingTool
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-SnippingTool-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SnippingTool-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-SnippingTool-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SnippingTool-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:ActiveDirectory
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-ActiveDirectory
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-ActiveDirectory
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-DirectoryServices-ADAM-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-DirectoryServices-ADAM-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-DirectoryServices-ADAM-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-DirectoryServices-ADAM-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:Containers
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Containers
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-Containers
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-OneCore-Containers-Opt-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-OneCore-Containers-Opt-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-OneCore-Containers-Opt-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-OneCore-Containers-Opt-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:AssignedAccess
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-AssignedAccess
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-AssignedAccess
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (

reg delete "%Packages%\Microsoft-Windows-Client-AssignedAccess-base-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Client-AssignedAccess-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Client-AssignedAccess-base-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Client-AssignedAccess-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Client-AssignedAccess-base-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Client-AssignedAccess-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Client-AssignedAccess-base-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Client-AssignedAccess-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:DeviceLockdown
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-DeviceLockdown
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-DeviceLockdown
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Embedded-BootExp-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-EmbeddedLogon-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-KeyboardFilter-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-ShellLauncher-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-base-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Client-EmbeddedExp-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Client-ShellLauncher-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-BootExp-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-EmbeddedLogon-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-KeyboardFilter-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-ShellLauncher-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-base-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Client-EmbeddedExp-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Client-ShellLauncher-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Embedded-BootExp-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-EmbeddedLogon-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-KeyboardFilter-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-ShellLauncher-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-base-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Client-EmbeddedExp-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Client-ShellLauncher-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-BootExp-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-EmbeddedLogon-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-KeyboardFilter-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-ShellLauncher-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-base-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Embedded-UnifiedWriteFilter-Merged-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Client-EmbeddedExp-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Client-ShellLauncher-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------


:Hyper-V
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Hyper-V
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-Hyper-V
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\HyperV-Guest-DynamicMemory-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Heartbeat-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Heartbeat-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-IcSvcExt-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-IcSvcExt-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-KMCL-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-KvpExchange-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-KvpExchange-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Networking-Emulated-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Networking-SrIov-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Networking-SrIov-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-RemoteFx-onecoreuap-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-RemoteFx-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Shutdown-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Shutdown-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Filter-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Filter-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Synthetic-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Synthetic-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-TimeSync-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-TimeSync-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-VmBus-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-VmBus-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-HvSocket-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Storage-VHD-Drivers-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Storage-VHD-Drivers-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Hyper-V-ClientEdition-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-HyperV-Guest-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-HyperV-Guest-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:HyperV-Guest-DynamicMemory-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Heartbeat-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Heartbeat-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-IcSvcExt-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-IcSvcExt-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-KMCL-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-KvpExchange-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-KvpExchange-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Networking-Emulated-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Networking-SrIov-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Networking-SrIov-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-RemoteFx-onecoreuap-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-RemoteFx-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Shutdown-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Shutdown-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Filter-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Filter-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Synthetic-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Synthetic-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-TimeSync-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-TimeSync-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-VmBus-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-VmBus-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-HvSocket-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Storage-VHD-Drivers-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Storage-VHD-Drivers-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Hyper-V-ClientEdition-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-HyperV-Guest-onecore-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-HyperV-Guest-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\HyperV-Guest-DynamicMemory-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Heartbeat-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Heartbeat-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-IcSvcExt-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-IcSvcExt-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-KMCL-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-KvpExchange-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-KvpExchange-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Networking-Emulated-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Networking-SrIov-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Networking-SrIov-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-RemoteFx-onecoreuap-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-RemoteFx-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Shutdown-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Shutdown-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Filter-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Filter-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Synthetic-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-Storage-Synthetic-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-TimeSync-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-TimeSync-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-VmBus-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Guest-VmBus-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-HvSocket-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Storage-VHD-Drivers-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\HyperV-Storage-VHD-Drivers-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Hyper-V-ClientEdition-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-HyperV-Guest-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-HyperV-Guest-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:HyperV-Guest-DynamicMemory-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Heartbeat-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Heartbeat-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-IcSvcExt-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-IcSvcExt-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-KMCL-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-KvpExchange-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-KvpExchange-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Networking-Emulated-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Networking-SrIov-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Networking-SrIov-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-RemoteFx-onecoreuap-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-RemoteFx-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Shutdown-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Shutdown-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Filter-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Filter-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Synthetic-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-Storage-Synthetic-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-TimeSync-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-TimeSync-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-VmBus-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Guest-VmBus-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-HvSocket-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Storage-VHD-Drivers-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:HyperV-Storage-VHD-Drivers-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Hyper-V-ClientEdition-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-HyperV-Guest-onecore-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-HyperV-Guest-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:InternetExplorer11
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-InternetExplorer11
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-InternetExplorer11
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~~11.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-InternetExplorer-Package~31bf3856ad364e35~amd64~~11.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~amd64~~11.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-InternetExplorer-Package~31bf3856ad364e35~amd64~~11.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~x86~~11.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-InternetExplorer-Package~31bf3856ad364e35~x86~~11.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-InternetExplorer-Optional-Package~31bf3856ad364e35~x86~~11.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-InternetExplorer-Package~31bf3856ad364e35~x86~~11.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
echo.Restart Windows to complete this operation.
choice /c YN /n /m "Do you want to restart the computer now? (Yes/No) "
if %errorlevel% EQU 1 goto Restart
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:LegacyComponents
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-LegacyComponents
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-LegacyComponents
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Legacy-Components-OC-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Legacy-Components-OC-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Legacy-Components-OC-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Legacy-Components-OC-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:MediaFeatures
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MediaFeatures
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-MediaFeatures
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-MediaPlayback-OC-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-MediaPlayback-OC-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-MediaPlayback-OC-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-MediaPlayback-OC-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:MessageQueue
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MessageQueue
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-MessageQueue
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-COM-MSMQ-package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-MSMQ-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-COM-MSMQ-package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-MSMQ-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-COM-MSMQ-package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-MSMQ-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-COM-MSMQ-package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-MSMQ-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:PrinttoPDF
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-PrinttoPDF
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-PrinttoPDF
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Printing-PrintToPDFServices-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Printing-PrintToPDFServices-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Printing-PrintToPDFServices-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Printing-PrintToPDFServices-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:MultiPointConnector
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-MultiPointConnector
if %errorlevel% EQU 2 goto Menu
: ------------------------------------------------------------------------------------

:Remove-MultiPointConnector
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-MultiPoint-Connector-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-MultiPoint-Connector-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-MultiPoint-Connector-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-MultiPoint-Connector-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:PrintandDocument
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-PrintandDocument
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-PrintandDocument
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-Foundation-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-LocalPrinting-Enterprise-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-LocalPrinting-Home-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-PremiumTools-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-Foundation-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-LocalPrinting-Enterprise-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-LocalPrinting-Home-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-PremiumTools-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-Foundation-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-LocalPrinting-Enterprise-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-LocalPrinting-Home-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-Printing-PremiumTools-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Printer-Drivers-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-Foundation-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-LocalPrinting-Enterprise-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-LocalPrinting-Home-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-Printing-PremiumTools-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:RASConnectionManager
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-RASConnectionManager
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-RASConnectionManager
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-RasCMAK-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-RasCMAK-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-RasCMAK-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-RasCMAK-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:DifferentialCompressionAPI
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-DifferentialCompressionAPI
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-DifferentialCompressionAPI
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-RDC-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-RDC-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-RDC-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-RDC-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:RIPListener
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-RIPListener
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-RIPListener
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-RasRip-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-RasRip-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-RasRip-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-RasRip-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:ServicesforNFS
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-ServicesforNFS
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-ServicesforNFS
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-NFS-ClientSKU-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-NFS-ClientSKU-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-NFS-ClientSKU-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-NFS-ClientSKU-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:SimpleNetwork
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-SimpleNetwork
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-SimpleNetwork
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-SNMP-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-WMI-SNMP-Provider-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SNMP-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-WMI-SNMP-Provider-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-SNMP-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-WMI-SNMP-Provider-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SNMP-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-WMI-SNMP-Provider-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:SimpleTCPIP
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-SimpleTCPIP
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-SimpleTCPIP
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-SimpleTCP-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SimpleTCP-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-SimpleTCP-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SimpleTCP-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:FileSharingSupport
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-FileSharingSupport
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-FileSharingSupport
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-SMB1-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SMB1-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-SMB1-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-SMB1-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
: ------------------------------------------------------------------------------------

:TelnetClient
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-TelnetClient
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-TelnetClient
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Telnet-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-TFTP-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Telnet-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-TFTP-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Telnet-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
reg delete "%Packages%\Microsoft-Windows-TFTP-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Telnet-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
dism /online /remove-package /packagename:Microsoft-Windows-TFTP-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:IdentifyFoundation
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-IdentifyFoundation
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-IdentifyFoundation
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Identity-Foundation-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Identity-Foundation-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Identity-Foundation-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Identity-Foundation-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:Powershell2.0
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-Powershell2.0
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-Powershell2.0
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-PowerShell-V2-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-PowerShell-V2-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-PowerShell-V2-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-PowerShell-V2-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:TIFFIFilter
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-TIFFIFilter
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-TIFFIFilter
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-WinOcr-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-WinOcr-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-WinOcr-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-WinOcr-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:XPSServices
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-XPSServices
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-XPSServices
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Printing-XPSServices-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Printing-XPSServices-Package~31bf3856ad364e35~amd64~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Printing-XPSServices-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Printing-XPSServices-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:XPSViewer
cls
choice /c YN /n /m "WARNING: This feature can not be reinstalled after remove. Are you sure? (Yes/No) "
if %errorlevel% EQU 1 goto Remove-XPSViewer
if %errorlevel% EQU 2 goto Menu
:: ------------------------------------------------------------------------------------

:Remove-XPSViewer
cls
IF %PROCESSOR_ARCHITECTURE% == AMD64 (
reg delete "%Packages%\Microsoft-Windows-Xps-Foundation-Client-Package~31bf3856ad364e35~amd64~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Xps-Foundation-Client-Package~31bf3856ad364e35~amd6~~10.0.15063.0 /norestart
) ELSE (
reg delete "%Packages%\Microsoft-Windows-Xps-Foundation-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0\Owners" /f
dism /online /remove-package /packagename:Microsoft-Windows-Xps-Foundation-Client-Package~31bf3856ad364e35~x86~~10.0.15063.0 /norestart
)
cls
echo.The operation completed successfully.
choice /c YN /n /m "Do you want to continue the program? (Yes/No) "
if %errorlevel% EQU 1 goto Menu
if %errorlevel% EQU 2 goto Close
:: ------------------------------------------------------------------------------------

:Close
cls
echo.The program will be closed after 15 seconds.
echo.Thank you for using my program.
echo.Any details please contact me through: fb.com/kequaduongvodanh
echo.Goodbye and see you again!
timeout /t 15 /nobreak
exit
:: ------------------------------------------------------------------------------------

:Restart
cls
echo.Windows will be restarted after 15 seconds.
echo.Thank you for using my program.
echo.Any details please contact me through: fb.com/kequaduongvodanh
echo.Goodbye and see you again!
timeout /t 15 /nobreak
shutdown /r /f /t 00
:: ------------------------------------------------------------------------------------

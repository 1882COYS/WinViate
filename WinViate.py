import os
import winreg as wrg
import shutil
import subprocess

listLength = 44

def list():

    print('WinViate v1.0')
    print("\n")
    print('1 - Turn On Game Mode - Game mode is a Windows setting designed to improve performance when gaming')
    print('2 - Turn Off Notifications - Removes notifications')
    print('3 - Disable Telemetry - Telemetry is an automatic process where Microsoft collects data from your pc')
    print('4 - Disable Wi-Fi Sense - Wi-Fi Sense is a data collection tool for public networks')
    print('5 - Delete Temp Files - Deletes temporary files that are not in use')
    print('6 - Disk Cleanup - Disk cleanup cleans unnecessary files')
    print('7 - Disable Location Tracking - Location tracking sends your location to third parties')
    print('8 - Disable Storage Sense - Storage sense cleans up windows, but there are better third-party programs')
    print('9 - Disable Hibernation - Stops windows going into hibernation mode, good for ssd health')
    print('10 - Disable GameDVR - GameDVR records gameplay footage in the background')
    print('11 - Disable Search Indexer - Search indexer looks at files and stores their info, resulting in faster searches but higher CPU usage')
    print('12 - Increase Priority Of IRQ8 - Interrupt Request for Real-Time Clock allowing pc to run slightly faster')
    print('13 - Disable Windows Time Service - Windows Time service synchronizes computer clocks via the network')
    print('14 - Disable Tablet Input Service - Tablet input service optimizes touch screen on devices')
    print('15 - Disable Prefetch Service - Prefetch service maintains and improves system performance over time, disable if using SATA or NVMe SSDs')
    print('16 - Disable Superfetch Service - Leave unless necessary, can cause issues')
    print('17 - Disable Printer Spooling Service - The printer spooling service manages the printing process')
    print('18 - Disable SMBv1 Protocol - The SMBv1 protocol is depreciated and is a big security risk')
    print('19 - Disable SMBv2 Protocol - The SMBv2 protocol is still in use but a slight security risk')
    print('20 - Disable Homegroup - Homegroup is used for file sharing, but is not used much anymore')
    print('21 - Disable Fax Service - Fax service is used for use with a fax machine')
    print('22 - Disable Error Reporting - Error reporting process that handles error reports')
    print('23 - Disable Cortana - Cortana is an ai personal assistant that is being discontinued')
    print('24 - Disable Xbox Live - Xbox Live is for Xbox users and is useless if you are not')
    print('25 - Remove Xbox Game Bar - Xbox game bar has a plethora of tools for gaming but can slow down pc')
    print('26 - Disable Windows Ink - Windows Ink adds pen support to Windows')
    print('27 - Disable Cloud Clipboard - Cloud clipboard allows the clipboard to be sent to others via the cloud')
    print('28 - Disable Windows Web Search - Disables Windows Web search')
    print('29 - Disable SmartScreen - Microsoft Defender SmartScreen protects against phishing or malware websites and applications, and the downloading of potentially malicious files')
    print('30 - Disable Windows Customer experience improvement program - The Customer Experience Improvement Program collects your computer systems information and usage patterns and sends it to Microsoft')
    print('31 - Disable Biometrics - Windows biometrics helps strengthen authentication and guards against spoofing')
    print('32 - Disable Remote Desktop - Remote desktop allows other computers to connect and control your pc')
    print('33 - Disable Smart Card Support - Smart card support adds the basic infrastructure for smart cards')
    print('34 - Disable Program Compatibility Assistant - Windows program compatibility assistant allows older programs to work better')
    print('35 - Disable Task scheduler - Task scheduler performs tasks at a designated time')
    print('36 - Disable OneDrive - OneDrive uses up performance and if not used, a PC can benefit from having it disabled')
    print('37 - Disable Windows Insider Program Settings - Windows Insider Program Settings are settings for the latter')
    print('38 - Disable Mobile Hotspot Service - Moblie Hotspot Service turns your PC into a mobile hotspot')
    print('39 - Disable Remote Registry - Remote Registry allows another windows PC to edit your registry')
    print('40 - Disable Wallet Service - Wallet Service is a digital wallet service that allows users to make payments')
    print('41 - Disable Downloaded Maps Manager - Downloaded Maps Manager updates downloaded offline maps')
    print('42 - Disable Certificate Propagation Service - the Certificate Propagation Service reads the certificate of user inserted smart cards')
    print('43 - Disable Windows OneSyncSvc - the OneSyncSvc synchronizes your microsoft apps')
    print('44 - Disable Windows Updates - Windows Updates update the windows version on your PC')
    print('\n')


def enableTweak():
    global tweak
    apply = 0

    # Game Mode
    if tweak == 1:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\GameBar'
        sub_key = 'AutoGameModeEnabled'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # Notifications
    elif tweak == 2:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\PushNotifications'
        sub_key = 'ToastEnabled'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # telemetry
    elif tweak == 3:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        sub_key = 'Allow Telemetry'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # Disable Wi-Fi scense
    elif tweak == 4:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
        sub_key = 'AutoConnectAllowedOEM'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # Clear Temp Files
    elif tweak == 5:
        shutil.rmtree(r"C:\Windows\Temp")
        shutil.rmtree(r"C:\Users\ADMINI~1\AppData\Local\Temp")
    
    # disk cleanup
    elif tweak == 6:
        clean=os.popen('cleanmgr.exe /sagerun:1').read()

    # Location
    elif tweak == 7:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        sub_key = 'Value'
        enabled = 'Deny'
        apply = 1
        type = wrg.REG_SZ

    #Storage Sense
    elif tweak == 8:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
        sub_key = '01'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #hibernation
    elif tweak == 9:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\Power'
        sub_key = 'HibernateEnabledDefault'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD
    
    #GameDVR part 1
    elif tweak == 10:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\GameDVR'
        sub_key = 'AppCaptureEnabled'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #GameDVR part 2
    #tweak set to 1010 to avoid user input and only occur when specified in code
    elif tweak == 1010:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'System\GameConfigStore'
        sub_key = 'GameDVR_Enabled'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #search indexing
    elif tweak == 11:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\WSearch'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    #IRQ8 priority
    elif tweak == 12:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\PriorityControl'
        sub_key = 'IRQ8Priority'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD
    
    #time service
    elif tweak == 13:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\W32Time'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    #tablet service
    elif tweak == 14:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\TabletMode'
        sub_key = "TabletMode"
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #prefetch
    elif tweak == 15:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        sub_key = "EnablePrefetcher"
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD
    
    #superfetch 
    elif tweak == 16:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\SysMain'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD
    
    # printer spooling
    elif tweak == 17:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\Spooler'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    # SMBv1
    elif tweak == 18:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        sub_key = 'SMB1'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #SMBv2
    elif tweak == 19:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        sub_key = 'SMB2'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # homegroup
    elif tweak == 20:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Classes\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}'
        sub_key = 'System.IsPinnedToNameSpaceTree'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # fax
    elif tweak == 21:
       root_key = wrg.HKEY_LOCAL_MACHINE
       k = 'SYSTEM\CurrentControlSet\Services\Fax'
       sub_key = 'Start'
       enabled = 4
       apply = 1
       type = wrg.REG_DWORD

    # windows error reporting
    elif tweak == 22:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        sub_key = 'Disabled'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # cortana
    elif tweak == 23:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        sub_key = 'AllowCortana'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # xbox live
    elif tweak == 24:
        os.system('cmd /k sc stop "Xbox Accessory Management Service" && sc config "Xbox Accessory Management Service" start=disabled')
        os.system('cmd /k sc stop "Xbox Live Auth Manager" && sc config "Xbox Live Auth Manager" start=disabled')
        os.system('cmd /k sc stop "Xbox Live Game Save" && sc config "Xbox Live Game Save" start=disabled')
        os.system('cmd /k sc stop "Xbox Live Networking Service" && sc config "Xbox Live Networking Service" start=disabled')

    # xbox game bar
    elif tweak == 25:
        subprocess.call('C:\Windows\System32\powershell.exe Get-AppxPackage Microsoft.XboxGamingOverlay -AllUsers | Remove-AppxPackage', shell=True)

    # ink
    elif tweak == 26:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft'
        sub_key = 'WindowsInkWorkspace'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # cloud clipboard
    elif tweak == 27:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\System'
        sub_key = 'AllowCrossDeviceClipboard'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # windows web search
    elif tweak == 28:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Policies\Microsoft\Windows\Explorer'
        sub_key = 'DisableSearchBoxSuggestions'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # smart screen
    elif tweak == 29:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\System'
        sub_key = 'EnableSmartScreen'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # windows customer experience
    elif tweak == 30:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\SQMClient'
        sub_key = 'Windows'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # biometrics
    elif tweak == 31:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Biometrics\Credential'
        sub_key = 'Domain Accounts'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # remote desktop
    elif tweak == 32:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
        sub_key = 'fDenyTSConnections'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # smart card support
    elif tweak == 33:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        sub_key = 'scforeoption'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # compatability
    elif tweak == 34:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\AppCompat'
        sub_key = 'DisablePCA'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # task scheduler part 1
    elif tweak == 35:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\Task Scheduler5.0'
        sub_key = 'Task Creation'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # task scheduler part 2
    elif tweak == 3535:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\Task Scheduler5.0'
        sub_key = 'Task Deletion'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # task scheduler part 3
    elif tweak == 353535:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\Task Scheduler5.0'
        sub_key = 'Execution'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # OneDrive
    elif tweak == 36:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\OneDrive'
        sub_key = 'DisableFileSyncNGSC'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # windows insider program
    elif tweak == 37:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows'
        sub_key = 'AllowBuildPreview'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # mobile hotspot
    elif tweak == 38:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = r'SOFTWARE\Policies\Microsoft\Windows\Network Connections'
        sub_key = 'NC_ShowSharedAccessUI'
        enabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # remote registry
    elif tweak == 39:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\RemoteRegistry'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    # wallet seervice
    elif tweak == 40:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\WalletService'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    # downloaded maps manager
    elif tweak == 41:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\MapsBroker'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    # Certificate Propagation
    elif tweak == 42:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\CertPropSvc'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    # OneSyncSvc
    elif tweak == 43:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\OneSyncSvc'
        sub_key = 'Start'
        enabled = 4
        apply = 1
        type = wrg.REG_DWORD

    # Windows update
    elif tweak == 44:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        sub_key = 'NoWindowsUpdate'
        enabled = 1
        apply = 1
        type = wrg.REG_DWORD


    #Apply Tweak
    if apply == 1:

        # create specifies the full location of the key
        create = (root_key, k)

        # is anything in the try fails, it diverts to except
        try:

            # attemps to open key specified from tweak
            key = wrg.OpenKey(root_key, k, 0, wrg.KEY_WRITE)

            print('Key Opened')

            # sets value of the sub key to value specified in tweak
            wrg.SetValueEx(key, sub_key, 0, type, enabled)

            print('Key Value Changed')

            # closes key
            wrg.CloseKey(key)

            print('Restart PC To Apply Changes')

        except:
            
            print('Key Not Found, Creating...')

            # creates key is it isnt present
            key = wrg.CreateKey(create, sub_key)

            print('Key Created')

            # attemps to open key specified from tweak
            key = wrg.OpenKey(root_key, k, 0, wrg.KEY_WRITE)

            print('Key Opened')

            # sets value of the sub key to value specified in tweak
            wrg.SetValueEx(key, sub_key, 0, type, enabled)

            print('Key Changed')

            # closes key
            wrg.CloseKey(key)

            print('Restart PC To Apply Changes')
    
    # switches to second part of tweak #10
    if tweak == 10:
        tweak = 1010
        print('Changing Next Value')
        enableTweak()

    # switches to second part of tweak #35
    if tweak == 35:
        tweak = 3535
        print('Changing Next Value')
        enableTweak()

    # switches to third part of tweak #35
    if tweak == 3535:
        tweak = 353535
        print('Changing Next Value')
        enableTweak()

def disableTweak():
    global tweak
    apply = 0

    #Game Mode
    if tweak == 1:

        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\GameBar'
        sub_key = 'AutoGameModeEnabled'
        disabled = 0
        apply = 1
        type = wrg.REG_DWORD
        

    # Notifications
    elif tweak == 2:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\PushNotifications'
        sub_key = 'ToastEnabled'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # Telemetry
    elif tweak == 3:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        sub_key = 'Allow Telemetry'
        disabled= 1
        apply = 1
        type = wrg.REG_DWORD

    
    # Wi-Fi scense
    elif tweak == 4:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
        sub_key = 'AutoConnectAllowedOEM'
        disabled = 1
        apply = 0
        type = wrg.REG_DWORD

    # Temp Files
    elif tweak == 5:
        print('You Cant Disable This Tweak!')

    # Disk Clean
    elif tweak == 6:
        print('You Cant Disable This Tweak! ')

    # Locations
    elif tweak == 7:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        sub_key = 'Value'
        disabled = 'Allow'
        apply = 0
        type = wrg.REG_SZ

    #Storage Sense
    elif tweak == 8:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
        sub_key = '01'
        disabled = 0
        apply = 0
        type = wrg.REG_DWORD

    #hibernation
    elif tweak == 9:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\Power'
        sub_key = 'HibernateEnabledDefault'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD
    
    #GameDVR part 1
    elif tweak == 10:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\GameDVR'
        sub_key = 'AppCaptureEnabled'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    #GameDVR part 2
    #tweak set to 1010 to avoid user input and only occur when specified in code
    elif tweak == 1010:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'System\GameConfigStore'
        sub_key = 'GameDVR_Enabled'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    #search indexing
    elif tweak == 11:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\WSearch'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    #IRQ8 priority
    elif tweak == 12:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\PriorityControl'
        sub_key = 'IRQ8Priority'
        disabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #Time service
    elif tweak == 13:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\W32Time'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    #tablet service
    elif tweak == 14:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\TabletMode'
        sub_key = "TabletMode"
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    #prefetch
    elif tweak == 15:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        sub_key = "EnablePrefetcher"
        disable = 1
        apply = 1
        type = wrg.REG_DWORD

    # superfetch
    elif tweak == 16:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\SysMain'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    # print spooler
    elif tweak == 17:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\Spooler'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    #SMBv1
    elif tweak == 18:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        sub_key = 'SMB1'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    #SMBv2
    elif tweak == 19:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        sub_key = 'SMB2'
        disabled = 1
        apply = 0
        type = wrg.REG_DWORD

    # homegroup
    elif tweak == 20:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Classes\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}'
        sub_key = 'System.IsPinnedToNameSpaceTree'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # fax
    elif tweak == 21:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\Fax'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD
    
    # windows error reporting
    elif tweak == 22:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        sub_key = 'Disabled'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # cortana
    elif tweak == 23:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        sub_key = 'AllowCortana'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # xbox live
    elif tweak == 24:
        os.system('cmd /k sc config "Xbox Accessory Management Service" start=delayed-auto && sc start "Fax')
        os.system('cmd /k sc config "Xbox Live Auth Manager" start=delayed-auto && sc start "Xbox Live Auth Manager')
        os.system('cmd /k sc config "Xbox Live Game Save" start=delayed-auto && sc start "Xbox Live Game Save')
        os.system('cmd /k sc config "Xbox Live Networking Service" start=delayed-auto && sc start "Xbox Live Networking Service')

    # game bar
    elif tweak == 25:
        subprocess.call('C:\Windows\System32\powershell.exe winget install Xbox Game Bar', shell=True)

    # ink
    elif tweak == 26:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft'
        sub_key = 'WindowsInkWorkspace'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # cloud clipboard
    elif tweak == 27:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\System'
        sub_key = 'AllowCrossDeviceClipboard'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD
    
    # windows web search
    elif tweak == 28:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Policies\Microsoft\Windows\Explorer'
        sub_key = 'DisableSearchBoxSuggestions'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # smart screen
    elif tweak == 29:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\System'
        sub_key = 'EnableSmartScreen'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # windows customer experience
    elif tweak == 30:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\SQMClient'
        sub_key = 'Windows'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # biometrics
    elif tweak == 31:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Biometrics\Credential'
        sub_key = 'Domain Accounts'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # remote desktop
    elif tweak == 32:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
        sub_key = 'fDenyTSConnections'
        disabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # samrt card support
    elif tweak == 33:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        sub_key = 'scforeoption'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # compatability
    elif tweak == 34:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\AppCompat'
        sub_key = 'DisablePCA'
        disabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # task scheduler part 1
    elif tweak == 35:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\Task Scheduler5.0'
        sub_key = 'Task Creation'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # task scheduler part 2
    elif tweak == 3535:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\Task Scheduler5.0'
        sub_key = 'Task Deletion'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # task scheduler part 3
    elif tweak == 353535:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'Software\Policies\Microsoft\Windows\Task Scheduler5.0'
        sub_key = 'Execution'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # OneDrive
    elif tweak == 36:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows\OneDrive'
        sub_key = 'DisableFileSyncNGSC'
        disabled = 0
        apply = 1
        type = wrg.REG_DWORD

    # windows insider program
    elif tweak == 37:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SOFTWARE\Policies\Microsoft\Windows'
        sub_key = 'AllowBuildPreview'
        disabled = 1
        apply = 1
        type = wrg.REG_DWORD

    # mobile hotspot
    elif tweak == 38:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = r'SOFTWARE\Policies\Microsoft\Windows\Network Connections'
        sub_key = 'NC_ShowSharedAccessUI'
        disabled = 1
        type = wrg.REG_DWORD

    # remote registry
    elif tweak == 39:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\RemoteRegistry'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    # wallet service
    elif tweak == 40:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\WalletService'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    # downloaded maps manager
    elif tweak == 41:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\MapsBroker'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    # certificate propagation
    elif tweak == 42:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\CertPropSvc'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    #OneSyncSvc
    elif tweak == 43:
        root_key = wrg.HKEY_LOCAL_MACHINE
        k = 'SYSTEM\CurrentControlSet\Services\OneSyncSvc'
        sub_key = 'Start'
        disabled = 2
        apply = 1
        type = wrg.REG_DWORD

    # windows update
    elif tweak == 44:
        root_key = wrg.HKEY_CURRENT_USER
        k = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        sub_key = 'NoWindowsUpdate'
        disabled = 0
        apply = 1
        type = wrg.REG_DWORD

    #Apply Tweak
    if apply == 1:

        # create specifies the full location of the key
        create = (root_key, k)
        try:
            key = wrg.OpenKey(root_key, k, 0, wrg.KEY_WRITE)

            print('Key Opened')

            wrg.SetValueEx(key, sub_key, 0, type, disabled)

            print('Key Changed')

            wrg.CloseKey(key)

            print('Restart PC To Apply Changes')

        except:
            
            print('Key Not Found, Creating...')

            key = wrg.CreateKey(create, sub_key)

            print('Key Created')

            key = wrg.OpenKey(root_key, k, 0, wrg.KEY_WRITE)

            print('Key Opened')

            wrg.SetValueEx(key, sub_key, 0, type, disabled)

            print('Key Changed')

            wrg.CloseKey(key)

            print('Restart PC To Apply Changes')

    if tweak == 10:
        tweak = 1010
        print('Changing Next Value')
        disableTweak()

    if tweak == 35:
        tweak = 3535
        print('Changing Next Value')
        disableTweak()

    if tweak == 3535:
        tweak = 353535
        print('Changing Next Value')
        disableTweak()
            

for i in range (1, listLength):
    list()    
    eOrD = input("Do you want to enable or disable a tweak? (e to enable d to disable)")
    tweak = int(input("What tweak do you want?(1 for game mode, 2 for notifications etc..)"))
    if eOrD == "e":
        enableTweak()
    elif eOrD == "d":
        disableTweak()
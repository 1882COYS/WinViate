import PySimpleGUI as sg
import os
import winreg as wrg
import shutil
import subprocess

sg.change_look_and_feel('DarkBlack') 

# ----------- Create the 3 layouts this Window will display -----------

# Creates all the checkboxes for page 1
layout1 = [[sg.Text('This is page 1')],
          [sg.CB('Turn On Game Mode              ', default=False, key='1'), sg.CB('Turn Off Notifications', default=False, key='2')],       
          [sg.CB('Disable Telemetry                  ', default=False, key='3'), sg.CB('Disable Wi-Fi Sense', default=False, key='4')],
          [sg.CB('Delete Temp Files                  ', default=False, key='5'), sg.CB('Disk Cleanup', default=False, key='6')],
          [sg.CB('Disable Location Tracking       ', default=False, key='7'), sg.CB('Disable Storage Sense', default=False, key='8')],
          [sg.CB('Disable Hibernation                ', default=False, key='9'), sg.CB('Disable GameDVR', default=False, key='10')],
          [sg.CB('Disable Search Indexer           ', default=False, key='11'), sg.CB('Increase Priority Of IRQ8', default=False, key='12')],
          [sg.CB('Disable Windows Time Service', default=False, key='13'), sg.CB('Disable Tablet Input Service', default=False, key='14')],
          [sg.CB('Disable Prefetch Service    ', default=False, key='15')]]

# Creates all the checkboxes for page 2
layout2 = [[sg.Text('This is page 2')],
          [sg.CB('Disable Superfetch Service      ', default=False, key = '16'), sg.CB('Disable Printer Spooling Service', default=False, key = '17')],
          [sg.CB('Disable SMBv1 Protocol         ', default=False, key = '18'), sg.CB('Disable SMBv2 Protocol', default=False, key = '19')],
          [sg.CB('Disable Homegroup                ', default=False, key = '20'), sg.CB('Disable Fax Service', default=False, key = '21')],
          [sg.CB('Disable Error Reporting           ', default=False, key = '22'), sg.CB('Disable Cortana', default=False, key = '23')],
          [sg.CB('Disable Xbox Live                   ', default=False, key = '24'), sg.CB('Remove Xbox Game Bar', default=False, key = '25')],
          [sg.CB('Disable Windows Ink              ', default=False, key = '26'), sg.CB('Disable Cloud Clipboard', default=False, key = '27')],
          [sg.CB('Disable Windows Web Search', default=False, key = '28'), sg.CB('Disable SmartScreen', default=False, key = '29')],
          [sg.CB('Disable Windows Customer experience improvement program', default=False, key = '30')]]

# Creates all the checkboxes for page 3
layout3 = [[sg.Text('This is page 3')],
          [sg.CB('Disable Biometrics                                  ', default=False, key = '31'), sg.CB('Disable Remote Desktop', default=False, key = '32')],
          [sg.CB('Disable Smart Card Support                     ', default=False, key = '33'), sg.CB('Disable Program Compatibility Assistant', default=False, key = '34')],
          [sg.CB('Disable Task scheduler                            ', default=False, key = '35'), sg.CB('Disable OneDrive', default=False, key = '36')],
          [sg.CB('Disable Windows Insider Program Settings', default=False, key = '37'), sg.CB('Disable Mobile Hotspot Service', default=False, key = '38')],
          [sg.CB('Disable Remote Registry                          ', default=False, key = '39'), sg.CB('Disable Wallet Service', default=False, key = '40')],
          [sg.CB('Disable Downloaded Maps Manager          ', default=False, key = '41'), sg.CB('Disable Certificate Propagation Service', default=False, key = '42')],
          [sg.CB('Disable Windows OneSyncSvc                 ', default=False, key = '43'), sg.CB('Disable Windows Updates', default=False, key = '44')]]
          

# ----------- Create actual layout using Columns and a row of Buttons
layout = [[sg.Button('Page 1'), sg.Button('Page 2'), sg.Button('Page 3'), sg.Button('Exit')],
         [sg.Column(layout1, key='-COL1-'), sg.Column(layout2, visible=False, key='-COL2-'), sg.Column(layout3, visible=False, key='-COL3-')],
         [sg.Button('Apply'), sg.Button('Disable')]]

# Names the windows WinViate
window = sg.Window('WinViate GUI', layout)

# The currently visible layout
layout = 1  

#Apply Tweak
def applyTweak():

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

# Disable Tweak
def disableTweak():

        # create specifies the full location of the key
        create = (root_key, k)
        try:
            # attemps to open key specified from tweak
            key = wrg.OpenKey(root_key, k, 0, wrg.KEY_WRITE)

            print('Key Opened')

             # sets value of the sub key to value specified in tweak
            wrg.SetValueEx(key, sub_key, 0, type, disabled)

            print('Key Changed')

            # Closes key
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
            wrg.SetValueEx(key, sub_key, 0, type, disabled)

            print('Key Changed')

            # closes key
            wrg.CloseKey(key)

            print('Restart PC To Apply Changes')

# Loops forever
while True:
    event, values = window.read()
    print(event, values)

    # Makes program stop when exit pressed
    if event in (None, 'Exit'):
        break

    if event == 'Page 1':
        window[f'-COL{layout}-'].update(visible=False)
        layout = 1
        window[f'-COL{layout}-'].update(visible=True)

    if event == 'Page 2':
        window[f'-COL{layout}-'].update(visible=False)
        layout = 2
        window[f'-COL{layout}-'].update(visible=True)

    if event == 'Page 3':
        window[f'-COL{layout}-'].update(visible=False)
        layout = 3
        window[f'-COL{layout}-'].update(visible=True)

    # Makes program switch to next layout when next page button is pressed
    if event == 'Next Layout':
        window[f'-COL{layout}-'].update(visible=False)
        layout = layout + 1 if layout < 3 else 1
        window[f'-COL{layout}-'].update(visible=True)
    elif event in '123':
        window[f'-COL{layout}-'].update(visible=False)
        layout = int(event)
        window[f'-COL{layout}-'].update(visible=True)

# When apply pressed
    if event == 'Apply':

        # Game Mode
        if values['1'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\GameBar'
            sub_key = 'AutoGameModeEnabled'
            enabled = 1
            type = wrg.REG_DWORD
            values['1'] == False
            applyTweak()

        # Notifications
        if values['2'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\PushNotifications'
            sub_key = 'ToastEnabled'
            enabled = 0
            type = wrg.REG_DWORD
            applyTweak()

        # Telemetry
        if values['3'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            sub_key = 'Allow Telemetry'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # Wifi Sense
        if values['4'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
            sub_key = 'AutoConnectAllowedOEM'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()
        
        # Clean Temp Files
        if values['5'] == True:
            del_dir = r"C:\Users\ADMINI~1\AppData\Local\Temp"
            subprocess.Popen('rmdir /S /Q %s' % del_dir, shell=True, stdout = subprocess.PIPE, stderr= subprocess.PIPE)
            del_dir = r"C:\windows\temp"
            subprocess.Popen('rmdir /S /Q %s' % del_dir, shell=True, stdout = subprocess.PIPE, stderr= subprocess.PIPE)

        # disk cleanup
        if values['6'] == True:
            os.popen('cleanmgr.exe /sagerun:1').read()

        # Location
        if values['7'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
            sub_key = 'Value'
            enabled = 'Deny'
            apply = 1
            type = wrg.REG_SZ
            applyTweak()

        #Storage Sense
        if values['8'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
            sub_key = '01'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()
        
        #hibernation
        if values['9'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\Power'
            sub_key = 'HibernateEnabledDefault'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()
        
        #GameDVR part 1
        if values['10'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\GameDVR'
            sub_key = 'AppCaptureEnabled'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_CURRENT_USER
            k = 'System\GameConfigStore'
            sub_key = 'GameDVR_Enabled'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # Search indexing
        if values['11'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\WSearch'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        #IRQ8 priority
        if values['12'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\PriorityControl'
            sub_key = 'IRQ8Priority'
            enabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        #time service
        if values['13'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\W32Time'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        #tablet service
        if values['14'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\TabletInputService'
            sub_key = "Start"
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        #prefetch
        if values['15'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
            sub_key = "EnablePrefetcher"
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        #superfetch 
        if values['16'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\SysMain'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # printer spooling
        if values['17'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\Spooler'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # SMBv1
        if values['18'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            sub_key = 'SMB1'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        #SMBv2
        if values['19'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            sub_key = 'SMB2'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # homegroup
        if values['20'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\HomeGroupListener'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\HomeGroupProvider'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # fax
        if values['21'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\Fax'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # windows error reporting
        if values['22'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'
            sub_key = 'Disabled'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # cortana
        if values['23'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            sub_key = 'AllowCortana'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # xbox live
        if values['24'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XblAuthManager'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XblGameSave'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = r'SYSTEM\CurrentControlSet\Services\xboxgip'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XboxGipSvc'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XboxNetApiSvc'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()
            

        # xbox game bar
        if values['25'] == True:
            subprocess.call('C:\Windows\System32\powershell.exe Get-AppxPackage Microsoft.XboxGamingOverlay -AllUsers | Remove-AppxPackage', shell=True)

        # ink
        if values['26'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft'
            sub_key = 'WindowsInkWorkspace'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # cloud clipboard
        if values['27'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\System'
            sub_key = 'AllowCrossDeviceClipboard'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # windows web search
        if values['28'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Policies\Microsoft\Windows\Explorer'
            sub_key = 'DisableSearchBoxSuggestions'
            enabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # smart screen
        if values['29'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\System'
            sub_key = 'EnableSmartScreen'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # windows customer experience
        if values['30'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\SQMClient'
            sub_key = 'Windows'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # biometrics
        if values['31'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Biometrics'
            sub_key = 'Enabled'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # remote desktop
        if values['32'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
            sub_key = 'fDenyTSConnections'
            enabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # smart card support
        if values['33'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            sub_key = 'scforeoption'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()
        
        # compatability
        if values['34'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows\AppCompat'
            sub_key = 'DisablePCA'
            enabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # task scheduler
        if values['35'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows'
            sub_key = 'Task Creation'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows'
            sub_key = 'Task Deletion'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows'
            sub_key = 'Execution'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # OneDrive
        if values['36'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\OneDrive'
            sub_key = 'DisableFileSyncNGSC'
            enabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # windows insider program
        if values['37'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows'
            sub_key = 'AllowBuildPreview'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # mobile hotspot
        if values['38'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = r'SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            sub_key = 'NC_ShowSharedAccessUI'
            enabled = 0
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # remote registry
        if values['39'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\RemoteRegistry'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # wallet service
        if values['40'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\WalletService'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # downloaded maps manager
        if values['41'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\MapsBroker'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            applyTweak()

        # Certificate Propagation
        if values['42'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\CertPropSvc'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # OneSyncSvc
        if values['43'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\OneSyncSvc'
            sub_key = 'Start'
            enabled = 4
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # Windows update
        if values['44'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            sub_key = 'NoWindowsUpdate'
            enabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

# When disabled pressed
    if event == 'Disable':

        # Game mode
        if values['1'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\GameBar'
            sub_key = 'AutoGameModeEnabled'
            disabled = 0
            type = wrg.REG_DWORD
            disableTweak()

        # Notifications
        if values['2'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\PushNotifications'
            sub_key = 'ToastEnabled'
            disabled = 1
            type = wrg.REG_DWORD
            disableTweak()

        # Telemetry
        if values ['3'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            sub_key = 'Allow Telemetry'
            disabled= 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # Wifi Sense
        if values ['4'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
            sub_key = 'AutoConnectAllowedOEM'
            disabled = 1
            apply = 0
            type = wrg.REG_DWORD
            disableTweak()

        # Locations
        if values['7'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
            sub_key = 'Value'
            disabled = 'Allow'
            apply = 0
            type = wrg.REG_SZ
            disableTweak()

        #Storage Sense
        if values['8'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
            sub_key = '01'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD

        #hibernation
        if values['9'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\Power'
            sub_key = 'HibernateEnabledDefault'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD

        #GameDVR part 1
        if values['10'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\GameDVR'
            sub_key = 'AppCaptureEnabled'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

            root_key = wrg.HKEY_CURRENT_USER
            k = 'System\GameConfigStore'
            sub_key = 'GameDVR_Enabled'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # Search indexing
        if values['11'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\WSearch'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        #IRQ8 priority
        if values['12'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\PriorityControl'
            sub_key = 'IRQ8Priority'
            disabled = 0
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        #time service
        if values['13'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\W32Time'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        #tablet service
        if values['14'] == True:
            oot_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\TabletInputService'
            sub_key = "Start"
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        #prefetch
        if values['15'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
            sub_key = "EnablePrefetcher"
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        #superfetch 
        if values['16'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\SysMain'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # printer spooling
        if values['17'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\Spooler'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # SMBv1
        if values['18'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            sub_key = 'SMB1'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        #SMBv2
        if values['19'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            sub_key = 'SMB2'
            edisabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # homegroup
        if values['20'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\HomeGroupListener'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\HomeGroupProvider'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # fax
        if values['21'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\Fax'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # windows error reporting
        if values['22'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'
            sub_key = 'Disabled'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # cortana
        if values['23'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            sub_key = 'AllowCortana'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        
            # xbox live
        if values['24'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XblAuthManager'
            sub_key = 'Start'
            enabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XblGameSave'
            sub_key = 'Start'
            enabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = r'SYSTEM\CurrentControlSet\Services\xboxgip'
            sub_key = 'Start'
            enabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XboxGipSvc'
            sub_key = 'Start'
            enabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\XboxNetApiSvc'
            sub_key = 'Start'
            enabled = 2
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

        # game bar
        if values['25'] == True:
            subprocess.call('C:\Windows\System32\powershell.exe winget install Xbox Game Bar', shell=True)

        # ink
        if values['26'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft'
            sub_key = 'WindowsInkWorkspace'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # cloud clipboard
        if values['27'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\System'
            sub_key = 'AllowCrossDeviceClipboard'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # windows web search
        if values['28'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Policies\Microsoft\Windows\Explorer'
            sub_key = 'DisableSearchBoxSuggestions'
            disabled = 0
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # smart screen
        if values['29'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows\System'
            sub_key = 'EnableSmartScreen'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # windows customer experience
        if values['30'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\SQMClient'
            sub_key = 'Windows'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # biometrics
        if values['31'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Biometrics'
            sub_key = 'Enabled'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # remote desktop
        if values['32'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
            sub_key = 'fDenyTSConnections'
            disabled = 0
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # smart card support
        if values['33'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            sub_key = 'scforeoption'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # compatability
        if values['34'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows\AppCompat'
            sub_key = 'DisablePCA'
            disabled = 0
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # task scheduler
        if values['35'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows'
            sub_key = 'Task Creation'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows'
            sub_key = 'Task Deletion'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'Software\Policies\Microsoft\Windows'
            sub_key = 'Execution'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            applyTweak()

            # windows insider program
        if values['37'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SOFTWARE\Policies\Microsoft\Windows'
            sub_key = 'AllowBuildPreview'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # mobile hotspot
        if values['38'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = r'SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            sub_key = 'NC_ShowSharedAccessUI'
            disabled = 1
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # remote registry
        if values['39'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\RemoteRegistry'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # wallet service
        if values['40'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\WalletService'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

         # downloaded maps manager
        if values['41'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\MapsBroker'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            disableTweak()
        
        # Certificate Propagation
        if values['42'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\CertPropSvc'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # OneSyncSvc
        if values['43'] == True:
            root_key = wrg.HKEY_LOCAL_MACHINE
            k = 'SYSTEM\CurrentControlSet\Services\OneSyncSvc'
            sub_key = 'Start'
            disabled = 2
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()

        # Windows update
        if values['44'] == True:
            root_key = wrg.HKEY_CURRENT_USER
            k = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            sub_key = 'NoWindowsUpdate'
            disabled = 0
            apply = 1
            type = wrg.REG_DWORD
            disableTweak()
    

window.close()
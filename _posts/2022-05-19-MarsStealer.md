---
title: "Deep Analysis of Mars Stealer"
classes: wide

ribbon: DodgerBlue
header:
  teaser: /assets/malware-analysis/Mars/logo1.gif
description: "Mars Stealer is an improved copy of Oski Stealer. "
categories:
  - Malware Analysis
tags:
  - Stealer
toc: true
---


# Introduction

Mars Stealer is an improved copy of Oski Stealer. I saw alot of tweets recently about it so i decided to write an analysis of the newer version V8. Enjoy reading!
- Diffrences from the previous version:
1. Anti analysis technique
2. Diffrent encryption algoithm
3. Introudcing new anti debug technique
4. New configuration format
4. External dlls are in one zip file

# Overview


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/overview.png"> 
</p> 
# Anti-Analysis 

Opening mars stealer in ida we can see an  anti-analysis trick called Opaque Predicates it’s a commonly used technique in program obfuscation, intended to add complexity to the control flow. 

This obfuscation simply takes an absolute jump (JMP) and transforms it into two conditional jumps (JZ/JNZ). Depending on the value of the Zero flag (ZF), the execution will follow the first or second branch.

However, disassemblers are tricked into thinking that there is a fall-through branch if the second jump is not taken (which is impossible as one of them must be taken) and tries to disassemble the unreachable instructions (often invalid) resulting in garbage code.


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/1.png"> 
</p> 

the deobfuscation is simple, we just need to patch the first conditional jump to an absolute jump and nop out the second jump, we can use IDAPython to achieve this:


```python
import idc

ea = 0
while True:
    ea =  min(ida_search.find_binary(ea,idc.BADADDR, "74 ? 75 ?",16 ,idc.SEARCH_NEXT | idc.SEARCH_DOWN),  # JZ / JNZ
    ida_search.find_binary(ea,idc.BADADDR, "75 ? 74 ?",16, idc.SEARCH_NEXT | idc.SEARCH_DOWN))  # JNZ / JZ
    if ea == idc.BADADDR:
        break
    idc.patch_byte(ea, 0xEB)
    idc.patch_byte(ea+2, 0x90)
    idc.patch_byte(ea+3, 0x90)
    idc.patch_byte(ea+4, 0x90)
```


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/2.png"> 
</p> 
<center><font size="3"> <u>After Running the Script </u></font> </center>

now we can see a clear view , after reversing and renaming

|[![0](/assets/malware-analysis/Mars/3.png)](/assets/malware-analysis/Mars/3.png)|[![0](/assets/malware-analysis/Mars/3-2.png)](/assets/malware-analysis/Mars/3-2.png)|



First Mars get a handle to kernel32.dll by parsing `InLoadOrderModuleList` then it passes the handle to a fucntion that  loops over the exported functions of the DLL to get the address of the `LocalAlloc()` and `VirtualProtect()` functions.


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/4.png"> 
</p> 
# String Encryption
After that it decrypts some strings used for some checks , the decryption is a simple xor function

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/5.png"> 
</p> 


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/6.png"> 
</p> 

We can although see that the xor function is refrenced in another function which i renamed as Decrypt_String_2 if the malware passes the checks which we will see soon it decrypt those string which contanis strings needed for the malware to steal sensitive data .

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/8.png"> 
</p> 

We use idapython script to get those strings and rename the variables to make reversing easier


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/7.png"> 
</p> 

```python
import string

def sanitize_string(name):
        return "".join([c for c in name if c in string.ascii_letters])[:20].capitalize()

def X0r(key, data, length):
    res = ""
    for i in range(length):
        res += chr(key[i] ^ data[i])
    return res


start_Addrs = [0x00401770,0x00401990  ]
end_Addrs = [0x00401967,0x0405444 ]

string_list = []
dectypred_data = b''
addrs = []

for i in range(len(start_Addrs)):
    ea = start_Addrs[i]
    end = end_Addrs[i]

    while ea <= end:
        if idc.get_operand_type(ea, 0) == idc.o_imm:
            addrs.append((idc.get_operand_value(ea, 0)))

        if len(addrs) == 3:
            length = addrs[0]
            data = idc.get_bytes(addrs[1], length)
            key = idc.get_bytes(addrs[2], length)
            dectypred_data = X0r(key, data, length)
            string_list.append(dectypred_data)
            addrs = []

        if idc.print_insn_mnem(ea) == "call":
            idc.set_cmt(ea, dectypred_data, 1)

        if idc.print_insn_mnem(ea) == "mov" and (idc.get_operand_type(ea, 0) == idc.o_mem) and (
                idc.get_operand_type(ea, 1) == idc.o_reg):
            global_var = idc.get_operand_value(ea, 0)
            idc.set_name(global_var, "Str" + sanitize_string(dectypred_data), SN_NOWARN)

        ea = idc.next_head(ea, end)


```

Here is a list of the decrypted strings : 


<details style="color: #EEFFFF; font-family: monospace !default; font-size: 0.85em; background: #263238; border: 1px solid #263238; border-radius: 3px; padding: 10px; line-height: 2.2; overflow-x: scroll;">
    <summary style="outline: none; cursor: pointer">
        <span style="color: darkgray">
            Expand to see more
        </span><br>
<div style="height: 1px"></div>
&emsp; LoadLibraryA<br>
&emsp; GetProcAddress<br>
&emsp; ExitProcess<br>
&emsp; advapi32.dll<br>
&emsp; crypt32.dll<br>
&emsp; GetTickCount<br>
&emsp; Sleep<br>
&emsp; GetUserDefaultLangID<br>
&emsp; CreateMutexA<br>
&emsp; GetLastError<br>
</summary>
&emsp; HeapAlloc<br>
&emsp; GetProcessHeap<br>
&emsp; GetComputerNameA<br>
&emsp; VirtualProtect<br>
&emsp; GetCurrentProcess<br>
&emsp; VirtualAllocExNuma<br>
&emsp; GetUserNameA<br>
&emsp; CryptStringToBinaryA<br>
&emsp; HAL9TH<br>
&emsp; JohnDoe<br>
&emsp; ­6Ê§È/2022 20:00:00<br>
&emsp; http://<br>
&emsp; 194.87.218.39<br>
&emsp; 92550737836278980100<br>
&emsp; /RyC66VfSGP.php<br>
&emsp; Default<br>
&emsp; %hu/%hu/%hu %hu:%hu:%hu<br>
&emsp; open<br>
&emsp; sqlite3.dll<br>
&emsp; C:\ProgramData\sqlite3.dll<br>
&emsp; freebl3.dll<br>
&emsp; C:\ProgramData\freebl3.dll<br>
&emsp; mozglue.dll<br>
&emsp; C:\ProgramData\mozglue.dll<br>
&emsp; msvcp140.dll<br>
&emsp; C:\ProgramData\msvcp140.dll<br>
&emsp; nss3.dll<br>
&emsp; C:\ProgramData\nss3.dll<br>
&emsp; softokn3.dll<br>
&emsp; C:\ProgramData\softokn3.dll<br>
&emsp; vcruntime140.dll<br>
&emsp; C:\ProgramData\vcruntime140.dll<br>
&emsp; .zip<br>
&emsp; Tag: <br>
&emsp; IP: IP?<br>
&emsp; Country: Country?<br>
&emsp; Working Path: <br>
&emsp; Local Time: <br>
&emsp; TimeZone: <br>
&emsp; Display Language: <br>
&emsp; Keyboard Languages: <br>
&emsp; Is Laptop: <br>
&emsp; Processor: <br>
&emsp; Installed RAM: <br>
&emsp; OS: <br>
&emsp;  (<br>
&emsp;  Bit)<br>
&emsp; Videocard: <br>
&emsp; Display Resolution: <br>
&emsp; PC name: <br>
&emsp; User name: <br>
&emsp; Domain name: <br>
&emsp; MachineID: <br>
&emsp; GUID: <br>
&emsp; Installed Software: <br>
&emsp; system.txt<br>
&emsp; Grabber\%s.zip<br>
&emsp; %APPDATA%<br>
&emsp; %LOCALAPPDATA%<br>
&emsp; %USERPROFILE%<br>
&emsp; %DESKTOP%<br>
&emsp; Wallets\<br>
&emsp; Ethereum<br>
&emsp; \Ethereum\<br>
&emsp; keystore<br>
&emsp; Electrum<br>
&emsp; \Electrum\wallets\<br>
&emsp; *.*<br>
&emsp; ElectrumLTC<br>
&emsp; \Electrum-LTC\wallets\<br>
&emsp; Exodus<br>
&emsp; \Exodus\<br>
&emsp; exodus.conf.json<br>
&emsp; window-state.json<br>
&emsp; \Exodus\exodus.wallet\<br>
&emsp; passphrase.json<br>
&emsp; seed.seco<br>
&emsp; info.seco<br>
&emsp; ElectronCash<br>
&emsp; \ElectronCash\wallets\<br>
&emsp; default_wallet<br>
&emsp; MultiDoge<br>
&emsp; \MultiDoge\<br>
&emsp; multidoge.wallet<br>
&emsp; JAXX<br>
&emsp; \jaxx\Local Storage\<br>
&emsp; file__0.localstorage<br>
&emsp; Atomic<br>
&emsp; \atomic\Local Storage\leveldb\<br>
&emsp; 000003.log<br>
&emsp; CURRENT<br>
&emsp; LOCK<br>
&emsp; LOG<br>
&emsp; MANIFEST-000001<br>
&emsp; 0000*<br>
&emsp; Binance<br>
&emsp; \Binance\<br>
&emsp; app-store.json<br>
&emsp; Coinomi<br>
&emsp; \Coinomi\Coinomi\wallets\<br>
&emsp; *.wallet<br>
&emsp; *.config<br>
&emsp; *wallet*.dat<br>
&emsp; GetSystemTime<br>
&emsp; lstrcatA<br>
&emsp; SystemTimeToFileTime<br>
&emsp; ntdll.dll<br>
&emsp; sscanf<br>
&emsp; memset<br>
&emsp; memcpy<br>
&emsp; wininet.dll<br>
&emsp; user32.dll<br>
&emsp; gdi32.dll<br>
&emsp; netapi32.dll<br>
&emsp; psapi.dll<br>
&emsp; bcrypt.dll<br>
&emsp; vaultcli.dll<br>
&emsp; shlwapi.dll<br>
&emsp; shell32.dll<br>
&emsp; gdiplus.dll<br>
&emsp; ole32.dll<br>
&emsp; dbghelp.dll<br>
&emsp; CreateFileA<br>
&emsp; WriteFile<br>
&emsp; CloseHandle<br>
&emsp; GetFileSize<br>
&emsp; lstrlenA<br>
&emsp; LocalAlloc<br>
&emsp; GlobalFree<br>
&emsp; ReadFile<br>
&emsp; OpenProcess<br>
&emsp; SetFilePointer<br>
&emsp; SetEndOfFile<br>
&emsp; GetCurrentProcessId<br>
&emsp; GetLocalTime<br>
&emsp; GetTimeZoneInformation<br>
&emsp; GetUserDefaultLocaleName<br>
&emsp; LocalFree<br>
&emsp; GetSystemPowerStatus<br>
&emsp; GetSystemInfo<br>
&emsp; GlobalMemoryStatusEx<br>
&emsp; IsWow64Process<br>
&emsp; GetTempPathA<br>
&emsp; GetLocaleInfoA<br>
&emsp; GetFileSizeEx<br>
&emsp; GetFileAttributesA<br>
&emsp; FindFirstFileA<br>
&emsp; FindNextFileA<br>
&emsp; FindClose<br>
&emsp; GetCurrentDirectoryA<br>
&emsp; CopyFileA<br>
&emsp; DeleteFileA<br>
&emsp; lstrcmpW<br>
&emsp; GlobalAlloc<br>
&emsp; FreeLibrary<br>
&emsp; SetCurrentDirectoryA<br>
&emsp; CreateFileMappingA<br>
&emsp; MapViewOfFile<br>
&emsp; UnmapViewOfFile<br>
&emsp; FileTimeToSystemTime<br>
&emsp; GetFileInformationByHandle<br>
&emsp; GlobalLock<br>
&emsp; GlobalSize<br>
&emsp; WideCharToMultiByte<br>
&emsp; GetWindowsDirectoryA<br>
&emsp; GetVolumeInformationA<br>
&emsp; GetVersionExA<br>
&emsp; GetModuleFileNameA<br>
&emsp; CreateFileW<br>
&emsp; CreateFileMappingW<br>
&emsp; MultiByteToWideChar<br>
&emsp; CreateThread<br>
&emsp; GetEnvironmentVariableA<br>
&emsp; SetEnvironmentVariableA<br>
&emsp; lstrcpyA<br>
&emsp; lstrcpynA<br>
&emsp; InternetOpenA<br>
&emsp; InternetConnectA<br>
&emsp; HttpOpenRequestA<br>
&emsp; HttpSendRequestA<br>
&emsp; HttpQueryInfoA<br>
&emsp; InternetCloseHandle<br>
&emsp; InternetReadFile<br>
&emsp; InternetSetOptionA<br>
&emsp; InternetOpenUrlA<br>
&emsp; InternetCrackUrlA<br>
&emsp; wsprintfA<br>
&emsp; CharToOemW<br>
&emsp; GetKeyboardLayoutList<br>
&emsp; EnumDisplayDevicesA<br>
&emsp; ReleaseDC<br>
&emsp; GetDC<br>
&emsp; GetSystemMetrics<br>
&emsp; GetDesktopWindow<br>
&emsp; GetWindowRect<br>
&emsp; GetWindowDC<br>
&emsp; CloseWindow<br>
&emsp; RegOpenKeyExA<br>
&emsp; RegQueryValueExA<br>
&emsp; RegCloseKey<br>
&emsp; GetCurrentHwProfileA<br>
&emsp; RegEnumKeyExA<br>
&emsp; RegGetValueA<br>
&emsp; CreateDCA<br>
&emsp; GetDeviceCaps<br>
&emsp; CreateCompatibleDC<br>
&emsp; CreateCompatibleBitmap<br>
&emsp; SelectObject<br>
&emsp; BitBlt<br>
&emsp; DeleteObject<br>
&emsp; StretchBlt<br>
&emsp; GetObjectW<br>
&emsp; GetDIBits<br>
&emsp; SaveDC<br>
&emsp; CreateDIBSection<br>
&emsp; DeleteDC<br>
&emsp; RestoreDC<br>
&emsp; DsRoleGetPrimaryDomainInformation<br>
&emsp; GetModuleFileNameExA<br>
&emsp; CryptUnprotectData<br>
&emsp; BCryptCloseAlgorithmProvider<br>
&emsp; BCryptDestroyKey<br>
&emsp; BCryptOpenAlgorithmProvider<br>
&emsp; BCryptSetProperty<br>
&emsp; BCryptGenerateSymmetricKey<br>
&emsp; BCryptDecrypt<br>
&emsp; VaultOpenVault<br>
&emsp; VaultCloseVault<br>
&emsp; VaultEnumerateItems<br>
&emsp; VaultGetItemWin8<br>
&emsp; VaultGetItemWin7<br>
&emsp; VaultFree<br>
&emsp; StrCmpCA<br>
&emsp; StrStrA<br>
&emsp; PathMatchSpecA<br>
&emsp; SHGetFolderPathA<br>
&emsp; ShellExecuteExA<br>
&emsp; GdipGetImageEncodersSize<br>
&emsp; GdipGetImageEncoders<br>
&emsp; GdipCreateBitmapFromHBITMAP<br>
&emsp; GdiplusStartup<br>
&emsp; GdiplusShutdown<br>
&emsp; GdipSaveImageToStream<br>
&emsp; GdipDisposeImage<br>
&emsp; GdipFree<br>
&emsp; CreateStreamOnHGlobal<br>
&emsp; GetHGlobalFromStream<br>
&emsp; SymMatchString<br>
&emsp; HEAD<br>
&emsp; HTTP/1.1<br>
&emsp; GET<br>
&emsp; POST<br>
&emsp; file<br>
&emsp; Content-Type: multipart/form-data; boundary=----<br>
&emsp; Content-Disposition: form-data; name="<br>
&emsp; Content-Disposition: form-data; name="file"; filename="<br>
&emsp; Content-Type: application/octet-stream<br>
&emsp; Content-Transfer-Encoding: binary<br>
&emsp; SOFT: <br>
&emsp; PROF: ?<br>
&emsp; PROF: <br>
&emsp; HOST: <br>
&emsp; USER: <br>
&emsp; PASS: <br>
&emsp; sqlite3_open<br>
&emsp; sqlite3_prepare_v2<br>
&emsp; sqlite3_step<br>
&emsp; sqlite3_column_text<br>
&emsp; sqlite3_finalize<br>
&emsp; sqlite3_close<br>
&emsp; sqlite3_column_bytes<br>
&emsp; sqlite3_column_blob<br>
&emsp; encrypted_key<br>
&emsp; "}<br>
&emsp; PATH<br>
&emsp; PATH=<br>
&emsp; NSS_Init<br>
&emsp; NSS_Shutdown<br>
&emsp; PK11_GetInternalKeySlot<br>
&emsp; PK11_FreeSlot<br>
&emsp; PK11_Authenticate<br>
&emsp; PK11SDR_Decrypt<br>
&emsp; SELECT origin_url, username_value, password_value FROM logins<br>
&emsp; Cookies\%s_%s.txt<br>
&emsp; SELECT HOST_KEY , is_httponly , path , is_secure , (expires_utc/1000000)-11644480800 , name , encrypted_value from cookies<br>
&emsp; TRUE<br>
&emsp; FALSE<br>
&emsp; Autofill\%s_%s.txt<br>
&emsp; SELECT name, value FROM autofill<br>
&emsp; CC\%s_%s.txt<br>
&emsp; SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards<br>
&emsp; Card number: <br>
&emsp; 
Name on card: <br>
&emsp; 
Expiration date: <br>
&emsp; History\%s_%s.txt<br>
&emsp; SELECT url FROM urls<br>
&emsp; Downloads\%s_%s.txt<br>
&emsp; SELECT target_path, tab_url from downloads<br>
&emsp; Login Data<br>
&emsp; Cookies<br>
&emsp; Web Data<br>
&emsp; History<br>
&emsp; SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies<br>
&emsp; logins.json<br>
&emsp; formSubmitURL<br>
&emsp; usernameField<br>
&emsp; encryptedUsername<br>
&emsp; encryptedPassword<br>
&emsp; guid<br>
&emsp; SELECT fieldname, value FROM moz_formhistory<br>
&emsp; SELECT url FROM moz_places<br>
&emsp; cookies.sqlite<br>
&emsp; formhistory.sqlite<br>
&emsp; places.sqlite<br>
&emsp; \Local State<br>
&emsp; ..\profiles.ini<br>
&emsp; C:\ProgramData\<br>
&emsp; Chrome<br>
&emsp; \Google\Chrome\User Data<br>
&emsp; ChromeBeta<br>
&emsp; \Google\Chrome Beta\User Data<br>
&emsp; ChromeCanary<br>
&emsp; \Google\Chrome SxS\User Data<br>
&emsp; Chromium<br>
&emsp; \Chromium\User Data<br>
&emsp; Edge_Chromium<br>
&emsp; \Microsoft\Edge\User Data<br>
&emsp; Kometa<br>
&emsp; \Kometa\User Data<br>
&emsp; Amigo<br>
&emsp; \Amigo\User Data<br>
&emsp; Torch<br>
&emsp; \Torch\User Data<br>
&emsp; Orbitum<br>
&emsp; \Orbitum\User Data<br>
&emsp; Comodo<br>
&emsp; \Comodo\Dragon\User Data<br>
&emsp; Nichrome<br>
&emsp; \Nichrome\User Data<br>
&emsp; Maxthon5<br>
&emsp; \Maxthon5\Users<br>
&emsp; Sputnik<br>
&emsp; \Sputnik\User Data<br>
&emsp; EPB<br>
&emsp; \Epic Privacy Browser\User Data<br>
&emsp; Vivaldi<br>
&emsp; \Vivaldi\User Data<br>
&emsp; CocCoc<br>
&emsp; \CocCoc\Browser\User Data<br>
&emsp; Uran<br>
&emsp; \uCozMedia\Uran\User Data<br>
&emsp; QIP<br>
&emsp; \QIP Surf\User Data<br>
&emsp; Cent<br>
&emsp; \CentBrowser\User Data<br>
&emsp; Elements<br>
&emsp; \Elements Browser\User Data<br>
&emsp; TorBro<br>
&emsp; \TorBro\Profile<br>
&emsp; CryptoTab<br>
&emsp; \CryptoTab Browser\User Data<br>
&emsp; Brave<br>
&emsp; \BraveSoftware\Brave-Browser\User Data<br>
&emsp; Opera<br>
&emsp; \Opera Software\Opera Stable\<br>
&emsp; OperaGX<br>
&emsp; \Opera Software\Opera GX Stable\<br>
&emsp; OperaNeon<br>
&emsp; \Opera Software\Opera Neon\User Data<br>
&emsp; Firefox<br>
&emsp; \Mozilla\Firefox\Profiles\<br>
&emsp; SlimBrowser<br>
&emsp; \FlashPeak\SlimBrowser\Profiles\<br>
&emsp; PaleMoon<br>
&emsp; \Moonchild Productions\Pale Moon\Profiles\<br>
&emsp; Waterfox<br>
&emsp; \Waterfox\Profiles\<br>
&emsp; Cyberfox<br>
&emsp; \8pecxstudios\Cyberfox\Profiles\<br>
&emsp; BlackHawk<br>
&emsp; \NETGATE Technologies\BlackHawk\Profiles\<br>
&emsp; IceCat<br>
&emsp; \Mozilla\icecat\Profiles\<br>
&emsp; KMeleon<br>
&emsp; \K-Meleon\<br>
&emsp; Thunderbird<br>
&emsp; \Thunderbird\Profiles\<br>
&emsp; passwords.txt<br>
&emsp; ibnejdfjmmkpcnlpebklmnkoeoihofec<br>
&emsp; TronLink<br>
&emsp; nkbihfbeogaeaoehlefnkodbefgpgknn<br>
&emsp; MetaMask<br>
&emsp; fhbohimaelbohpjbbldcngcnapndodjp<br>
&emsp; Binance Chain Wallet<br>
&emsp; ffnbelfdoeiohenkjibnmadjiehjhajb<br>
&emsp; Yoroi<br>
&emsp; jbdaocneiiinmjbjlgalhcelgbejmnid<br>
&emsp; Nifty Wallet<br>
&emsp; afbcbjpbpfadlkmhmclhkeeodmamcflc<br>
&emsp; Math Wallet<br>
&emsp; hnfanknocfeofbddgcijnmhnfnkdnaad<br>
&emsp; Coinbase Wallet<br>
&emsp; hpglfhgfnhbgpjdenjgmdgoeiappafln<br>
&emsp; Guarda<br>
&emsp; blnieiiffboillknjnepogjhkgnoapac<br>
&emsp; EQUAL Wallet<br>
&emsp; cjelfplplebdjjenllpjcblmjkfcffne<br>
&emsp; Jaxx Liberty<br>
&emsp; fihkakfobkmkjojpchpfgcmhfjnmnfpi<br>
&emsp; BitApp Wallet<br>
&emsp; kncchdigobghenbbaddojjnnaogfppfj<br>
&emsp; iWallet<br>
&emsp; amkmjjmmflddogmhpjloimipbofnfjih<br>
&emsp; Wombat<br>
&emsp; nlbmnnijcnlegkjjpcfjclmcfggfefdm<br>
&emsp; MEW CX<br>
&emsp; nanjmdknhkinifnkgdcggcfnhdaammmj<br>
&emsp; GuildWallet<br>
&emsp; nkddgncdjgjfcddamfgcmfnlhccnimig<br>
&emsp; Saturn Wallet<br>
&emsp; fnjhmkhhmkbjkkabndcnnogagogbneec<br>
&emsp; Ronin Wallet<br>
&emsp; cphhlgmgameodnhkjdmkpanlelnlohao<br>
&emsp; NeoLine<br>
&emsp; nhnkbkgjikgcigadomkphalanndcapjk<br>
&emsp; Clover Wallet<br>
&emsp; kpfopkelmapcoipemfendmdcghnegimn<br>
&emsp; Liquality Wallet<br>
&emsp; aiifbnbfobpmeekipheeijimdpnlpgpp<br>
&emsp; Terra Station<br>
&emsp; dmkamcknogkgcdfhhbddcghachkejeap<br>
&emsp; Keplr<br>
&emsp; fhmfendgdocmcbmfikdcogofphimnkno<br>
&emsp; Sollet<br>
&emsp; cnmamaachppnkjgnildpdmkaakejnhae<br>
&emsp; Auro Wallet<br>
&emsp; jojhfeoedkpkglbfimdfabpdfjaoolaf<br>
&emsp; Polymesh Wallet<br>
&emsp; flpiciilemghbmfalicajoolhkkenfel<br>
&emsp; ICONex<br>
&emsp; nknhiehlklippafakaeklbeglecifhad<br>
&emsp; Nabox Wallet<br>
&emsp; hcflpincpppdclinealmandijcmnkbgn<br>
&emsp; KHC<br>
&emsp; ookjlbkiijinhpmnjffcofjonbfbgaoc<br>
&emsp; Temple<br>
&emsp; mnfifefkajgofkcjkemidiaecocnkjeh<br>
&emsp; TezBox<br>
&emsp; dkdedlpgdmmkkfjabffeganieamfklkm<br>
&emsp; Cyano Wallet<br>
&emsp; nlgbhdfgdhgbiamfdfmbikcdghidoadd<br>
&emsp; Byone<br>
&emsp; infeboajgfhgbjpjbeppbkgnabfdkdaf<br>
&emsp; OneKey<br>
&emsp; cihmoadaighcejopammfbmddcmdekcje<br>
&emsp; LeafWallet<br>
&emsp; lodccjjbdhfakaekdiahmedfbieldgik<br>
&emsp; DAppPlay<br>
&emsp; ijmpgkjfkbfhoebgogflfebnmejmfbml<br>
&emsp; BitClip<br>
&emsp; lkcjlnjfpbikmcmbachjpdbijejflpcm<br>
&emsp; Steem Keychain<br>
&emsp; onofpnbbkehpmmoabgpcpmigafmmnjhl<br>
&emsp; Nash Extension<br>
&emsp; bcopgchhojmggmffilplmbdicgaihlkp<br>
&emsp; Hycon Lite Client<br>
&emsp; klnaejjgbibmhlephnhpmaofohgkpgkd<br>
&emsp; ZilPay<br>
&emsp; aeachknmefphepccionboohckonoeemg<br>
&emsp; Coin98 Wallet<br>
&emsp; bfnaelmomeimhlpmgjnjophhpkkoljpa<br>
&emsp; Phantom<br>
&emsp; hifafgmccdpekplomjjkcfgodnhcellj<br>
&emsp; Crypto.com<br>
&emsp; dngmlblcodfobpdpecaadgfbcggfjfnm<br>
&emsp; Maiar DeFi Wallet<br>
&emsp; ppdadbejkmjnefldpcdjhnkpbjkikoip<br>
&emsp; Oasis<br>
&emsp; hpbgcgmiemanfelegbndmhieiigkackl<br>
&emsp; MonstaWallet<br>
&emsp; fcckkdbjnoikooededlapcalpionmalo<br>
&emsp; MOBOX<br>
&emsp; jccapkebeeiajkkdemacblkjhhhboiek<br>
&emsp; Crust Wallet<br>
&emsp; mgffkfbidihjpoaomajlbgchddlicgpn<br>
&emsp; Pali Wallet<br>
&emsp; nphplpgoakhhjchkkhmiggakijnkhfnd<br>
&emsp; TON Wallet<br>
&emsp; ldinpeekobnhjjdofggfgjlcehhmanlj<br>
&emsp; Hiro Wallet<br>
&emsp; pocmplpaccanhmnllbbkpgfliimjljgo<br>
&emsp; Slope Wallet<br>
&emsp; bhhhlbepdkbapadjdnnojkbgioiodbic<br>
&emsp; Solflare Wallet<br>
&emsp; pgiaagfkgcbnmiiolekcfmljdagdhlcm<br>
&emsp; Stargazer Wallet<br>
&emsp; cgeeodpfagjceefieflmdfphplkenlfk<br>
&emsp; EVER Wallet<br>
&emsp; gjkdbeaiifkpoencioahhcilildpjhgh<br>
&emsp; partisia-wallet<br>
&emsp; bgjogpoidejdemgoochpnkmdjpocgkha<br>
&emsp; Ecto Wallet<br>
&emsp; ifckdpamphokdglkkdomedpdegcjhjdp<br>
&emsp; ONTO Wallet<br>
&emsp; agechnindjilpccclelhlbjphbgnobpf<br>
&emsp; Fractal Wallet<br>
&emsp; algblmhagnobbnmakepomicmfljlbehg<br>
&emsp; ADS Wallet<br>
&emsp; imijjbmbnebfnbmonjeileijahaipglj<br>
&emsp; Moonlet Wallet<br>
&emsp; kpjdchaapjheajadlaakiiigcbhoppda<br>
&emsp; ZEBEDEE<br>
&emsp; dlcobpjiigpikoobohmabehhmhfoodbb<br>
&emsp; Argent X StarkNet Wallet<br>
&emsp; bofddndhbegljegmpmnlbhcejofmjgbn<br>
&emsp; X-Wallet<br>
&emsp; mapbhaebnddapnmifbbkgeedkeplgjmf<br>
&emsp; Biport Wallet<br>
&emsp; kfdniefadaanbjodldohaedphafoffoh<br>
&emsp; Typhon Wallet<br>
&emsp; jaooiolkmfcmloonphpiiogkfckgciom<br>
&emsp; Twetch Wallet<br>
&emsp; aijcbedoijmgnlmjeegjaglmepbmpkpi<br>
&emsp; Leap Wallet<br>
&emsp; fhfffofbcgbjjojdnpcfompojdjjhdim<br>
&emsp; Lamden Wallet<br>
&emsp; agkfnefiabmfpanochlcakggnkdfmmjd<br>
&emsp; Earth Wallet<br>
&emsp; lpfcbjknijpeeillifnkikgncikgfhdo<br>
&emsp; Nami<br>
&emsp; fecfflganphcinpahcklgahckeohalog<br>
&emsp; Coin Wallet<br>
&emsp; ilhaljfiglknggcoegeknjghdgampffk<br>
&emsp; Beam Web Wallet<br>
&emsp; dklmlehijiaepdijfnbbhncfpcoeeljf<br>
&emsp; FShares Wallet<br>
&emsp; fkhebcilafocjhnlcngogekljmllgdhd<br>
&emsp; WAGMIswap.io Wallet<br>
&emsp; laphpbhjhhgigmjoflgcchgodbbclahk<br>
&emsp; BLUE - Worlds Safest and Simplest Wallet<br>
&emsp; mkjjflkhdddfjhonakofipfojoepfndk<br>
&emsp; Unification Web Wallet<br>
&emsp; jnldfbidonfeldmalbflbmlebbipcnle<br>
&emsp; Infinity Wallet<br>
&emsp; ellkdbaphhldpeajbepobaecooaoafpg<br>
&emsp; Fetch.ai Network Wallet<br>
&emsp; iokeahhehimjnekafflcihljlcjccdbe<br>
&emsp; Alby Wallet<br>
&emsp; omajpeaffjgmlpmhbfdjepdejoemifpe<br>
&emsp; xBull Wallet<br>
&emsp; pgojdfajgcjjpjnbpfaelnpnjocakldb<br>
&emsp; Sugarchain Wallet<br>
&emsp; pnndplcbkakcplkjnolgbkdgjikjednm<br>
&emsp; Tronium<br>
&emsp; fnnegphlobjdpkhecapkijjdkgcjhkib<br>
&emsp; Harmony<br>
&emsp; fhilaheimglignddkjgofkcbgekhenbh<br>
&emsp; Oxygen<br>
&emsp; cmbagcoinhmacpcgmbiniijboejgiahi<br>
&emsp; JustLiquidity Wallet<br>
&emsp; kmmolakhbgdlpkjkcjkebenjheonagdm<br>
&emsp; AlgoSigner<br>
&emsp; fnabdmcgpkkjjegokfcnfbpneacddpfh<br>
&emsp; Goldmint Lite Wallet<br>
&emsp; bgpipimickeadkjlklgciifhnalhdjhe<br>
&emsp; GeroWallet<br>
&emsp; hoighigmnhgkkdaenafgnefkcmipfjon<br>
&emsp; EO.Finance<br>
&emsp; nlgnepoeokdfodgjkjiblkadkjbdfmgd<br>
&emsp; Multi Wallet<br>
&emsp; nhihjlnjgibefgjhobhcphmnckoogdea<br>
&emsp; Waves Enterprise Wallet<br>
&emsp; ehibhohmlpipbaogcknmpmiibbllplph<br>
&emsp; Bluehelix Wallet<br>
&emsp; magbanejlegnbcppjljfhnmfmghialkl<br>
&emsp; Nebulas Wallet<br>
&emsp; fgkaeeikaoeiiggggbgdcjchmdfmamla<br>
&emsp; Vtimes<br>
&emsp; pnlfjmlcjdjgkddecgincndfgegkecke<br>
&emsp; Crocobit Wallet<br>
&emsp; bhghoamapcdpbohphigoooaddinpkbai<br>
&emsp; Authenticator<br>
&emsp; gaedmjdfmmahhbjefcbgaolhhanlaolb<br>
&emsp; Authy<br>
&emsp; oeljdldpnmdbchonielidgobddffflal<br>
&emsp; EOS Authenticator<br>
&emsp; ilgcnhelpchnceeipipijaljkblbcobl<br>
&emsp; GAuth Authenticator<br>
&emsp; imloifkgjagghnncjkhggdhalmcnfklk<br>
&emsp; Trezor Password Manager<br>
&emsp; %s\%s\Local Extension Settings\%s<br>
&emsp; %s\CURRENT<br>
&emsp; %s\%s\Sync Extension Settings\%s<br>
&emsp; %s\%s\IndexedDB\chrome-extension_%s_0.indexeddb.leveldb<br>
&emsp; Plugins\<br>
&emsp; HARDWARE\DESCRIPTION\System\CentralProcessor\0<br>
&emsp; ProcessorNameString<br>
&emsp; SOFTWARE\Microsoft\Windows NT\CurrentVersion<br>
&emsp; ProductName<br>
&emsp; x64<br>
&emsp; x86<br>
&emsp; DISPLAY<br>
&emsp; SOFTWARE\Microsoft\Cryptography<br>
&emsp; MachineGuid<br>
&emsp; SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall<br>
&emsp; DisplayName<br>
&emsp; DisplayVersion<br>
&emsp; screenshot.jpg<br>
&emsp; ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890<br>
&emsp; /c timeout /t 5 & del /f /q "%s" & exit<br>
&emsp; C:\Windows\System32\cmd.exe<br>
</details>
<br>

# Dynamic linking

The adress of `GetProcAddress()` and `LoadLibraryA()`  is retrieved by the same method in Dynamic_Linking_1  looping over the exported functions of the kernel32.DLL , then it uses  `LoadLibraryA()` to Load the specified module into the address space and get a handle that get passed to  `GetProcAddress()` to retrieve the address of an exported function from the specified dynamic-link library.  
Dynamic_Linking_2 is loading the APIs only needed to do some checks if it passes it will load others needed for stealing functionality.

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/11.png"> 
</p> 

dword_42774 is `GetProcAddress()` it is called in other function which is Dynamic_Linking_3 that will load other APIs needed for stealing functionality.

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/12.png"> 
</p> 

We use idapython to rename the global variables with the api name to make reversing easier


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/13.png"> 
</p> 

```python
import idc

start_Addrs = [0x00415F86,0x00415FC0 ,0x004161A0 ]
end_Addrs = [0x00415FB7,0x00416176,0x00417034]

string_list = []

for i in range(len(start_Addrs)):
    ea = start_Addrs[i]
    end = end_Addrs[i]

    while ea <= end:

        if (idc.print_insn_mnem(ea) == "push"  )and (idc.get_operand_type(ea, 0) == idc.o_imm):
            name = idc.get_strlit_contents(idc.get_operand_value(ea, 0)).decode()

        if (idc.print_insn_mnem(ea) == "mov"  and (idc.get_operand_type(ea, 0) == idc.o_reg)and (idc.get_operand_type(ea, 1) == idc.o_mem)) :
            temp_name = idc.get_name(idc.get_operand_value(ea, 1))
            if "Str_" == temp_name[0:4]:
                name = temp_name[4::]

        if (idc.print_insn_mnem(ea) == "mov") and (idc.get_operand_type(ea, 0) == idc.o_mem) and (idc.get_operand_type(ea, 1) == idc.o_reg):
            global_var = idc.get_operand_value(ea, 0)
            idc.set_name(global_var, name, SN_NOWARN)

        ea = idc.next_head(ea, end)
```

# Anti-Sandbox



Since a lot of sandboxes hook and bypass `Sleep()` preventing malware being idle over their execution time.
The malware first calls   `GetTickCount()` function that retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days, that is our first timestamp. Then calls the `Sleep()` to suspend itself for 16 seconds. calling `GetTickCount()` again gets our second timestamp . The malware checks if at least 12 seconds diffrence between the 2 timestampes . If the function returns flase it means that the `Sleep()` hasn’t been skipped the malware assumes that it is running in a sandbox and exits immediately.

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/15.png"> 
</p> 

# Anti-CIS

This is one of the easy tricks to check if the malware is not infected users from specific countries.


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/16.png"> 
</p> 

Mars checks the user language to determine if it’s part of the Commonwealth of Independent States (CIS) countrie it gets the user language ID by using GetUserDefaultLangID and it compares the user language ID to:



|Language ID|		Country|
| --- | --- |
|0x43F|		Kazakhstan|
|0x443|		Uzbekistan|
|0x82C|		Azerbaijan|
|0x43Fu|		Kazakhstan|
|0x419u|		Russia|
|0x423u|		Belarus|

If the user language ID matches one of the IDs above, it will exit.

# Anti-Emulation

If the malware is executed with the computer name `HAL9TH`  and the username with `JohnDoe`  it will exit . This check is done because it is the name given to the Windows Defender Emulator, this technique is used by malware to prevent itself from running in an emulated environment.

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/17.png"> 
</p> 

# Mutex

The malware creates a mutex object using `CreateMutexA()` to avoid having more than one instance running.  Then calls` GetLastError() `which gets the last error, and if the error code is equal to 183 (ERROR_ALREADY_EXIST) it means that mutex already exists and an instance of the malware is already running therefore malware exits.

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/18.png"> 
</p> 

# Anti-Debug

The malware create thread that checks `BeingDebugged` flag which is Special flag in system tables, which dwell in process memory and which an operation system sets, can be used to indicate that the process is being debugged. The states of these flags can be verified either by using specific API functions or examining the system tables in memory. 
If the malware is being debugged it exits . 
The thread is going to keep running until the malware finishes excution or the thread end the malware excution if its being debugged .



<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/19.png"> 
</p> 


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/20.png"> 
</p> 

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/21.png"> 
</p> 


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/22.png"> 
</p> 

# Expiration check

The Expiration date variable contains the date 26/04/2022 20:00:00.

Mars uses [GetSystemTime()](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime) to get current system date and time as [SYSTEMTIME](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime) structe, then calls `sscanf()` to parse the Expiration date to a SYSTEMTIME structe . [SystemTimeToFileTime()](https://docs.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetofiletime) take SYSTEMTIME structe as argument then convert it to file time and Expiration date although is converted to file time.

If the current time exceedes the Expiration time, the malware calls `ExitProcess()` to exit immediately.



<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/24.png"> 
</p> 
 

# Main Functionality


|[![0](/assets/malware-analysis/Mars/53.png)](/assets/malware-analysis/Mars/53.png)|[![0](/assets/malware-analysis/Mars/49.png)](/assets/malware-analysis/Mars/49.png)|

Mars generate random string that will be the name of the zip file contains stolen data.

The communications between c2 and the malware is described as:
1. sends a GET request to the C2 URL on the `/RyC66VfSGP.php` endpoint to grab its configuration .
2. fetches all DLLs on the `/request` endpoint, the libraries are zipped
3. Stolen data are posted to the C2 on the same URL used in step 1.

Dlls retrieved:

|DLL Name|Description|Save path	|
|---|---|---|
|sqlite3.dll| Enables SQLite related operations| none (mars doesnt write it on disk, parsed from memory)|
|freebl3.dll| Library for the NSS (Gecko-based browsers)|C:\ProgramData\freebl3.dll|
|mozglue.dll|	Mozilla Browser Library|C:\ProgramData\mozglue.dll|
|msvcp140.dll|	Visual C++ Runtime 2015|C:\ProgramData\msvcp140.dll|
|nss3.dll	|Network System Services Library (Gecko-based browsers)|C:\ProgramData\nss3.dll|
|softokn3.dll|	Mozilla Browser Library|C:\ProgramData\softokn3.dll|
|vcruntime140.dll|	Visual C++ Runtime 2015|C:\ProgramData\vcruntime140.dll|

Another diffrence from the last version is that sqlite3 isnt written on disk, it just get parsed and passed to another function to get handle to it and start loading needed function , the other dll are written . 

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/52.png"> 
</p> 
Since the C2 was down i got the pcap from [Hatching sandbox](https://tria.ge/220406-k1kttacaf2).
<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/26.png"> 
</p> 

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/27.png"> 
</p> 

## Understanding Configuration Format
configuration is base64 encoded

`MXwxfDF8MXwxfDVxRGxQdVZLb1J8RGlzY29yZHwwfCVBUFBEQVRBJVxkaXNjb3JkXExvY2FsIFN0b3JhZ2VcfCp8MXwwfDB8VGVsZWdyYW1
8MHwlQVBQREFUQSVcVGVsZWdyYW0gRGVza3RvcFx0ZGF0YVx8KkQ4NzdGNzgzRDVEM0VGOEMqLCptYXAqLCpjb25maWdzKnwxfDB8MHw=`

`1|1|1|1|1|5qDlPuVKoR|Discord|0|%APPDATA%\discord\Local Storage\ |*|1|0|0|Telegram|0|%APPDATA%\Telegram Desktop\tdata\ |*D877F783D5D3EF8C*,*map*,*configs*|1|0|0|`	

```python
import base64
config = base64.b64decode("MXwxfDF8MXwxfDVxRGxQdVZLb1J8RGlzY29yZHwwfCVBUFBEQVRBJVxkaXNjb3JkXExvY2FsIFN0b3JhZ2VcfCp8MXwwfDB8VGVsZWdyYW18MHwlQVBQREFUQSVcVGVsZWdyYW0gRGVza3RvcFx0ZGF0YVx8KkQ4NzdGNzgzRDVEM0VGOEMqLCptYXAqLCpjb25maWdzKnwxfDB8MHw=").decode()
config = config.split("|")
print("First Part : \n" ,config[0:6])
print("Second Part :" )
for i in range(6,len(config),7):
    print(config[i:i+7])
```

    First Part : 
     ['1', '1', '1', '1', '1', '5qDlPuVKoR']
    Second Part :
    ['Discord', '0', '%APPDATA%\\discord\\Local Storage\\', '*', '1', '0', '0']
    ['Telegram', '0', '%APPDATA%\\Telegram Desktop\tdata\\', '*D877F783D5D3EF8C*,*map*,*configs*', '1', '0', '0']
    


- First part



|Config|Meaning|
|---|---|
|1|	Downloads_history_Flag|	
|1|	Browser_History_Flag|
|1| Autofill_Flag|
|1|	ScreenShoot_Flag|
|1| Self_Deletion_Flag|	
|5qDlPuVKoR|Explorer Credentials FileName|

- Second part


|Config|Meaning|
|---|---|
|Discord|	name for the zip file – will contain all the stolen files that related to the current task.so the name for the zip will be name.zip.|	
|0| maybe max size (no indecation of use)|
| %APPDATA%\\discord\\Local Storage\\ |An environment variable name and folder name – a starting point for the recursive Grabber.|
|* |	A regex list – contains multiply parameters that are separated by “,” each one of them is a regex that represents a file type.|
|1| is_Recursive|	
|0|Write to zip enabled if 0|	
|0|Exclusion List|	




## Grabber 

lets dig into `Config_Grabber` function to see how you it works

after receiving the config we can see the it has a lot of `|` so it split the config with `|` delimiter and loop through the splited config.
the first part enables/disable some of the stealer functionality then it starts in part 2 which start grapping files wanted.


as example
> ['Discord', '0', '%APPDATA%\\discord\\Local Storage\\', '*', '1', '0', '0']

it start recurseively grabbing all files in `discord\\Local Storage\\`  under `%APPDATA%` and put them in discord.zip



|[![0](/assets/malware-analysis/Mars/30.png)](/assets/malware-analysis/Mars/30.png)|[![0](/assets/malware-analysis/Mars/31.png)](/assets/malware-analysis/Mars/31.png)|
|[![0](/assets/malware-analysis/Mars/32.png)](/assets/malware-analysis/Mars/32.png)|[![0](/assets/malware-analysis/Mars/33.png)](/assets/malware-analysis/Mars/33.png)|



If there is more than one regex as in  
> ['Telegram', '0', '%APPDATA%\\Telegram Desktop\tdata\\', '*D877F783D5D3EF8C*,*map*,*configs*', '1', '0', '0'] 

it loops through them and call `Recursive_Grabber` with each regex .




<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/34.png"> 
</p> 

## Browsers
Mars steals credentials from browsers by static paths. It has four different methods to steal data from different types of browses, like Gecko-based browsers, Opera, Internet Explorer and Chromium-based browsers.


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/43.png"> 
</p> 

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/44.png"> 
</p> 

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/45.png"> 
</p> 

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/46.png"> 
</p> 


### Data Extraction

All the extraction functions have the same scheme:
1. The malware saves the addresses of the functions from sqlite3.dll
- sqlite3_open
- sqlite3_prepare_v2
- sqlite3_step
- sqlite3_column_bytes
- sqlite3_column_blob
- sqlite3_column_text
- sqlite3_column_finalize
- sqlite3_column_close
2. It generates a random string (length of 8 characters) and copies the DB file to a temp folder named like the random
string – all the extractions methods will be on the copied DB.
In order to extract the data from the DB, the malware has to create the SQL query and query the DB using sqlite3.dll functions.
3. The malware opens the DB by using sqlite3_open and passes the DB path.
4. It calls to sqlite3_prepare_v2, the function gets a handle to DB and the SQL query and returns a statement handle.
5. By using sqlite3_column_bytes/sqlite3_column_blob/sqlite3_column_text, the malware can get the results from the queries
6. The Credentials in Chromium-based browsers DB are encrypted by DPAPI and, therefore, the malware uses the function CryptUnprotectData to decrypt the Credentials.

Mars steals information from the Windows Vault, which is the default storage vault for the credential manager information. This is done through the use of Vaultcli.dll, which encapsulates the necessary functions to access the Vault. The malware loops through its items using:

- VaultEnumerateVaults
- VaultOpenVault
- VaultEnumerateItems
- VaultGetItem
- VaultFree

### Targeted DB Files

|File Name|	Affected Software|
|---|---|
|History |Chromium-based browsers|
|Login Data |Chromium-based browsers|
|Cookies	 | Chromium-based browsers|
|Web Data	|Chromium-based browsers|
|formhistory.sqlite|	Gecko-based browsers|
|cookies.sqlite	|Gecko-based browsers|
|signongs.sqlite|	Gecko-based browsers|
|places.sqlite|	Gecko-based browsers|

### Queries Used

|Query|Target Browser| Enabled
|---|---|---|
|SELECT target_path, tab_url from downloads | chromium , opera| by default this feature is disabled,  enabled if Downloads_history_Flag is set to 1|
|  SELECT name, value FROM autofill| chromium , opera|by default this feature is disabled, enabled if Autofill_Flag is set to 1|
|SELECT url FROM urls|chromium , opera |  by default this feature is disabled,enabled if Browser_History_Flag is set to 1|
|SELECT action_url, username_value, password_value FROM logins|chromium , opera| enabled by default
|SELECT HOST_KEY, is_httponly, path, is_secure, (expires_utc/1000000)-11644480800, name, encrypted_value from cookies|chromium , opera|enabled by default
|SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards|chromium , opera|enabled by default
|SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies|gecko|enabled by default
|SELECT url FROM moz_places|gecko|by default this feature is disabled,enabled if Browser_History_Flag is set to 1
|SELECT fieldname, value FROM moz_formhistory|gecko|enabled by default



## Cryptocurrency Wallets via browser extensions 


Mars appears to also target additional Chrome-based browser extensions related to two-factor authentication (2FA) .


<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/51.png"> 
</p> 

Mars steal files from 3 folders :

1. \Local Extension Settings\Extension ID from Google Store
2. \Sync Extension Settings\ Extension ID from Google Store
3. \IndexedDB\Domain Name.indexeddb.leveldb

as example if the victim uses Google Chrome with a crypto browser wallet extension, the extension files will be stored in:

C:\Users\Username\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\Extension ID from Google Store
C:\Users\Username\AppData\Local\Google\Chrome\User Data\Default\Sync Extension Settings\ Extension ID from Google Store
C:\Users\Username\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\Domain Name.indexeddb.leveldb


|Type  |Extension name|  Extension id|
| --- | --- |--- |
|Crypto|	TronLink|	ibnejdfjmmkpcnlpebklmnkoeoihofec|
|Crypto|	MetaMask|	nkbihfbeogaeaoehlefnkodbefgpgknn|
|Crypto|	Binance Chain Wallet|	fhbohimaelbohpjbbldcngcnapndodjp|
|Crypto|	Yoroi	|ffnbelfdoeiohenkjibnmadjiehjhajb|
|Crypto|	Nifty Wallet|	jbdaocneiiinmjbjlgalhcelgbejmnid|
|Crypto|	Math Wallet|	afbcbjpbpfadlkmhmclhkeeodmamcflc|
|Crypto|	Coinbase Wallet|	hnfanknocfeofbddgcijnmhnfnkdnaad|
|Crypto|	Guarda|	hpglfhgfnhbgpjdenjgmdgoeiappafln|
|Crypto|	EQUAL Wallet|	blnieiiffboillknjnepogjhkgnoapac|
|Crypto|	Jaxx Liberty|	cjelfplplebdjjenllpjcblmjkfcffne|
|Crypto|	BitApp Wallet|	fihkakfobkmkjojpchpfgcmhfjnmnfpi|
|Crypto|	iWallet|	kncchdigobghenbbaddojjnnaogfppfj|
|Crypto|	Wombat|	amkmjjmmflddogmhpjloimipbofnfjih|
|Crypto|	MEW CX|	nlbmnnijcnlegkjjpcfjclmcfggfefdm|
|Crypto|	GuildWallet|	nanjmdknhkinifnkgdcggcfnhdaammmj|
|Crypto|	Saturn Wallet|	nkddgncdjgjfcddamfgcmfnlhccnimig|
|Crypto|	Ronin Wallet|	fnjhmkhhmkbjkkabndcnnogagogbneec|
|Crypto|	NeoLine|	cphhlgmgameodnhkjdmkpanlelnlohao|
|Crypto|	Clover Wallet|	nhnkbkgjikgcigadomkphalanndcapjk|
|Crypto|	Liquality Wallet|	kpfopkelmapcoipemfendmdcghnegimn|
|Crypto|	Terra Station|	aiifbnbfobpmeekipheeijimdpnlpgpp|
|Crypto|	Keplr|	dmkamcknogkgcdfhhbddcghachkejeap|
|Crypto|	Sollet|	fhmfendgdocmcbmfikdcogofphimnkno|
|Crypto|	Auro Wallet|	cnmamaachppnkjgnildpdmkaakejnhae|
|Crypto|	Polymesh Wallet|	jojhfeoedkpkglbfimdfabpdfjaoolaf|
|Crypto|	ICONex|	flpiciilemghbmfalicajoolhkkenfel|
|Crypto|	Nabox Wallet|	nknhiehlklippafakaeklbeglecifhad|
|Crypto|	KHC|	hcflpincpppdclinealmandijcmnkbgn|
|Crypto|	Temple|	ookjlbkiijinhpmnjffcofjonbfbgaoc|
|Crypto|	TezBox|	mnfifefkajgofkcjkemidiaecocnkjeh|
|Crypto|	Cyano Wallet|	dkdedlpgdmmkkfjabffeganieamfklkm|
|Crypto|	Byone|	nlgbhdfgdhgbiamfdfmbikcdghidoadd|
|Crypto|	OneKey|	infeboajgfhgbjpjbeppbkgnabfdkdaf|
|Crypto|	LeafWallet|	cihmoadaighcejopammfbmddcmdekcje|
|Crypto|	DAppPlay|	lodccjjbdhfakaekdiahmedfbieldgik|
|Crypto|	BitClip|	ijmpgkjfkbfhoebgogflfebnmejmfbml|
|Crypto|	Steem Keychain|	lkcjlnjfpbikmcmbachjpdbijejflpcm|
|Crypto| Nash Extension|	onofpnbbkehpmmoabgpcpmigafmmnjhl|
|Crypto|	Hycon Lite Client|	bcopgchhojmggmffilplmbdicgaihlkp|
|Crypto|	ZilPay|	klnaejjgbibmhlephnhpmaofohgkpgkd|
|Crypto|	Coin98 Wallet|	aeachknmefphepccionboohckonoeemg|
|2FA|	Authenticator|	bhghoamapcdpbohphigoooaddinpkbai|
|2FA|	Authy|	gaedmjdfmmahhbjefcbgaolhhanlaolb|
|2FA|	EOS Authenticator|	oeljdldpnmdbchonielidgobddffflal|
|2FA|	GAuth Authenticator|	ilgcnhelpchnceeipipijaljkblbcobl|
|2FA|	Trezor Password Manager|	imloifkgjagghnncjkhggdhalmcnfklk|

## Crypto Wallets

Mars does not just stop at targeting crypto currencies via browser extensions. Many people prefer not to use third-party applications and services to store their digital currency.
Mars will go through various folders looking for specific files related to cryptocurrency. 

The first paramter detmerines the path if 0 then it's under %appdata%  if 1 it's under %localappdata%
then it search for other wallets with regex `*wallet*.dat` under %appdata%

<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/36.png"> 
</p> 


Mars have dedicated functionality to target the following crypto wallets:

|Wallet name|Wallet folder|Regex|
|---|---|---|
|Ethereum	|%appdata%\Ethereum\	|keystore
|Electrum	|%appdata%\Electrum\wallets\ |	.|
|Electrum LTC|	%appdata%\Electrum-LTC\wallets\ |	.|
|Exodus	|%appdata%\Exodus\	|exodus.conf.json, window-state.json, \Exodus\exodus.wallet\, passphrase.json, seed.seco, info.seco|
|Electron Cash|	%appdata%\ElectronCash\wallets\ |	default_wallet|
|MultiDoge|	%appdata%\MultiDoge\	|multidoge.wallet|
|Jaxx	|%appdata%\jaxx\Local Storage\	|file__0.localstorage|
|Atomic	|%appdata%\atomic\Local Storage\leveldb\	|000003.log, CURRENT, LOCK, LOG, MANIFEST.000001, 0000*|
|Binance|	%appdata%\Binance\	|app-store.json|
|Coinomi|	%localappdata%\Coinomi\Coinomi\wallets\ |	`*.wallet, *.config `|
|Other wallets | %appdata%| `*wallet*.dat`|

## System info
The malware grabs system info and store it in system.txt file
1. IP and country
2. Working path to EXE file
3. Local time and time zone
4. Language system
5. Language keyboard layout
6. Notebook or desktop
7. Processor model
8. Computer name
9. User name
10. Domain computer name
11. Machine ID
12. GUID
13. Installed software and their versions

Mars althouge takes screenshot and then add all stolen files to a zip file which it will exfiltrate back to the c2 and get loader config.

## Loader

Malware gets loader config as a response after exfiltrating data.
This config looks like  download_URL|An environment variable name and folder name |startup_parameter| . 

After pasring the config Mars calls `download_file()` function with the url and a path which the file will be saved in . Then calls `ShellExecuteExA()` to execute executable with give paramters retrieved from the config.



<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/37.png"> 
</p> 
<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/38.png"> 
</p> 

# Self Deletion

Malware gets the path to itself by using `GetModuleFileName()` and calls `ShellExecuteExA()` which executes the following command 

`"C:/Windows/System32/cmd.exe" /c timeout /t 5 & del /f / path_To_file & exit`

After 5 seconds the executable will be deleted.



<p align="center">
<img  class="image" src="/assets/malware-analysis/Mars/39.png"> 
</p> 



# Generalized  idapython Script using patterns


```python
import idautils , idc, idaapi, ida_search, ida_bytes, ida_auto
import string



seg_mapping = {idaapi.getseg(x).name: (idaapi.getseg(x).start_ea, idaapi.getseg(x).end_ea) for x in
                   idautils.Segments()}
start = seg_mapping[0x1][0]
end = seg_mapping[0x1][1]
    
def sanitize_string(name):
    return "".join([c for c in name if c in string.ascii_letters])[:20].capitalize()

def Xor(key, data, length):
    res = ""
    for i in range(length):
        res += chr(key[i] ^ data[i])
    return res

def getData (addr):
    key_addr = idc.prev_head(addr)
    data_addr = idc.prev_head(key_addr)
    key_length_addr = idc.prev_head(data_addr)
    length = idc.get_operand_value(key_length_addr, 0)
    key = idc.get_bytes(idc.get_operand_value(key_addr,0),length)
    data =  idc.get_bytes(idc.get_operand_value(data_addr,0),length)
    return  key , data ,length


def rename_APIs(ea,end):
    
    func_addr = ea
    for i in range(20):
        if (idc.print_insn_mnem(ea) == "push"  )and (idc.get_operand_type(ea, 0) == idc.o_imm):
            name = idc.get_strlit_contents(idc.get_operand_value(ea, 0)).decode()
            break
        
        if (idc.print_insn_mnem(ea) == "mov"  and (idc.get_operand_type(ea, 0) == idc.o_reg)and (idc.get_operand_type(ea, 1) == idc.o_mem)) :
            temp_name = idc.get_name(idc.get_operand_value(ea, 1))
            if "Str_" == temp_name[0:4]:
                name = temp_name[4::]
                break        
        ea =  idc.prev_head(ea)
        
    ea = func_addr
    
    for i in range(20):
        if (idc.print_insn_mnem(ea) == "mov") and (idc.get_operand_type(ea, 0) == idc.o_mem) and (idc.get_operand_type(ea, 1) == idc.o_reg):
                global_var = idc.get_operand_value(ea, 0)
                idc.set_name(global_var, name, SN_NOWARN)
                return name         
        ea = idc.next_head(ea, end)


def API_resolve(start,end):
    Loadlibrarya_addr = 0x0
    GetProcAddress_pattern = "8B 55 ?? 52 8B 45 ?? 8B 4D ??  8B 55 ?? 03 14 ?? 52 E8 ?? ?? ?? ?? 83 C4 ??  85 C0 75 ??"
    GetProcAddress_addr = ida_search.find_binary(start, end, GetProcAddress_pattern, 16, idc.SEARCH_DOWN)
    GetProcAddress_addr = idaapi.get_func(GetProcAddress_addr).start_ea
    print('[*] Traget fucntion found at {}'.format(hex(GetProcAddress_addr)))

    for ref in idautils.XrefsTo(GetProcAddress_addr):
        addr = ref.frm
        x = rename_APIs(addr, end)
        if "Loadlibrarya" in x:
                Loadlibrarya_addr = idc.get_operand_value(idc.next_head(idc.next_head(addr, end), end), 0)


    new_GetProcAddress_addr = idc.get_operand_value(idc.next_head(idc.next_head(addr, end), end), 0)
    
    for ref in idautils.XrefsTo(new_GetProcAddress_addr):
        addr = ref.frm
        rename_APIs(addr, end)

    for ref in idautils.XrefsTo(Loadlibrarya_addr):
        addr = ref.frm
        rename_APIs(addr, end)

        
def Strings_resolve(start,end):
    xor_pattern = "8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be"
    xor_fun_addr = ida_search.find_binary(start, end, xor_pattern, 16, idc.SEARCH_DOWN)
    xor_fun_addr = idaapi.get_func(xor_fun_addr).start_ea
    print('[*] Traget fucntion found at {}'.format(hex(xor_fun_addr)))

    for ref in idautils.XrefsTo(xor_fun_addr):
        addr = ref.frm
        key, data, length = getData(addr)
        decrypt_string = Xor(key, data, length)
        idc.set_cmt(addr, decrypt_string, 1)
        ea = idc.next_head(idc.next_head(addr, end),end)
        global_var = idc.get_operand_value(ea, 0)
        idc.set_name(global_var, "Str_" + sanitize_string(decrypt_string), SN_NOWARN)
        
def Anit_Reverse():
    ea = 0
    while True:
        ea = min(ida_search.find_binary(ea, idc.BADADDR, "74 ? 75 ?", 16, idc.SEARCH_NEXT | idc.SEARCH_DOWN),
                 # JZ / JNZ
                 ida_search.find_binary(ea, idc.BADADDR, "75 ? 74 ?", 16,
                                        idc.SEARCH_NEXT | idc.SEARCH_DOWN))  # JNZ / JZ
        if ea == idc.BADADDR:
            break
        idc.patch_byte(ea, 0xEB)
        idc.patch_byte(ea + 2, 0x90)
        idc.patch_byte(ea + 3, 0x90)
        idc.patch_byte(ea + 4, 0x90)



def main():
    Anit_Reverse()
    Strings_resolve(start,end)
    API_resolve(start,end)

main()

```
for more Idapython scripts check my [repo](https://github.com/X-Junior/Malware-IDAPython-Scripts/) .

# IOCs

- Hashes:
1. md5 : 880924E5583978C615DD03FF89648093
2. sha1 : EF759F6ECA63D6B05A7B6E395DF3571C9703278B
3. sha256 : 4bcff4386ce8fadce358ef0dbe90f8d5aa7b4c7aec93fca2e605ca2cbc52218b
4. imphash : 4E06C011D59529BFF8E1F1C88254B928
4. ssdeep : 3072:U/E8k9fjpIg+zNch12KbAwSaSMtmSu4/bVBt4b8EG:U/E8k9bwz6/tJc/4xM8EG
- Mutex : 92550737836278980100
- Files: 
   1. C:\ProgramData\freebl3.dll
   2. C:\ProgramData\mozglue.dll
   3. C:\ProgramData\msvcp140.dll
   4. C:\ProgramData\nss3.dll
   5. C:\ProgramData\softokn3.dll
   6. C:\ProgramData\vcruntime140.dll
- C2 Server : 194.87.218.39
- C2 Domains: 
    1. http://194[.]87[.]218[.]39/request 
    2. http://194[.]87[.]218[.]39/RyC66VfSGP[.]php 


# YARA

```python
rule Mars_Stealer: Mars Stealer
{
    meta:
        Author = "X__Junior"
        Description = "Mars Stealer v8 Detection"

    strings:
        $xor ={8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be}
        $debug = {64 A1 30 00 00 00 80 78 02 00}
	$thread_func = {B8 01 00 00 00   85 ??  74 ?? E8 ?? ?? ?? ?? 85 ?? 74 ?? 6A 00 FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? EB ??}

        $api1 = "LocalAlloc" ascii
        $api2 = "VirtualProtect" ascii
        $api3 = "SetFileTime" ascii
        $api4 = "LocalFileTimeToFileTime" ascii
        $api5 = "HeapFree" ascii
        $api6 = "VirtualFree" ascii
        $api7 = "VirtualAlloc" ascii

        $s1 = "DPAPI" ascii
        $s2 = "memset" ascii
        $s3 = "msvcrt.dll" ascii
        $s4 = "_mbsnbcpy" ascii
        $s5 = "_mbsstr" ascii

    condition:
        uint16(0) == 0x5A4D and 2 of($api*) and 3 of($s*)  and $debug  and $xor  and $thread_func

}
```
# Conclusion

The last sample of mars i saw came packed with custom packer , easy to unpack with x32dbg by just setting a breakpoint on `VirtualAlloc()` , nothing else was changed except for the C2 .

# References
- Great analysis of the previous version [https://3xp0rt.com/posts/mars-stealer](https://3xp0rt.com/posts/mars-stealer)
- [https://lp.cyberark.com/rs/316-CZP-275/images/CyberArk-Labs-Racoon-Malware-wp.pdf](https://lp.cyberark.com/rs/316-CZP-275/images/CyberArk-Labs-Racoon-Malware-wp.pdf)
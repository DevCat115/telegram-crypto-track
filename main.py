import os.path
import re
from util import *
import requests
import sys, os
import concurrent.futures
import threading

last_block_bnb_number = 0
last_block_eth_number = 0
latest_tx_hashes = {}
last_run_time = 0
eth_usd_price = 0


class RateLimiter:
    def __init__(self, max_calls, interval):
        self.max_calls = max_calls
        self.interval = interval
        self.calls = 0
        self.lock = threading.Lock()

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            with self.lock:
                if self.calls == self.max_calls:
                    elapsed = time.time() - self.last_call_time
                    if elapsed < self.interval:
                        time.sleep(self.interval - elapsed)
                        self.calls = 0
                self.calls += 1
                self.last_call_time = time.time()
            return func(*args, **kwargs)

        return wrapper


@RateLimiter(max_calls=1, interval=1)
def wallet_check(wallet):
    global last_block_eth_number
    global latest_tx_hashes
    global last_run_time
    global eth_usd_price

    show_log('{} checking'.format(wallet))
    try:
        blockchain, wallet_address, rate = wallet.split(':')
        message_header = f'Wallet:{wallet_address}\nMEMO:{rate}\n'
    except:
        blockchain, wallet_address = wallet.split(':')
        message_header = f'{wallet_address}\n'
    transactions = get_wallet_transactions(wallet_address)
    for tx in transactions:
        tx_hash = tx['hash']
        tx_time = int(tx['timeStamp'])

        if tx_hash not in latest_tx_hashes and tx_time > last_run_time:

            last_block_eth_number = int(tx['blockNumber'])
            contract_address = tx['to']
            method_id = tx['methodId']
            input = tx['input']
            behavious = 'BUY'
            value = float(tx['value']) / 10 ** 18  # Convert from wei to ETH or BNB
            if contract_address.lower() == ETH_ROUTER_ADDRESS.lower():
                global eth_usd_price
                eth_usd_price = get_eth_price()
                usd_value = value * eth_usd_price
                # buy function
                if method_id == '0xfb3bdb41' or method_id == '0x7ff36ab5' or method_id == '0xb6f9de95':
                    token_address = '0x' + input[-40:]
                    token_name = get_tokensymbol(token_address)
                # sell function
                elif method_id == '0x18cbafe5' or method_id == '0x4a25d94a' or method_id == '0x791ac947':
                    token_address = '0x' + input[-104:-64]
                    token_name = get_tokensymbol(token_address)
                    behavious = "SELL"
                # token exchange
                elif method_id == '0x38ed1739' or method_id == '0x8803dbee' or method_id == '0x5c11d795':
                    token1_address = '0x' + input[-104:-64]
                    token_name = get_tokensymbol(token1_address)
                    behavious = "TOKEN SWAP"
                else:
                    return
                message = '{}Behaviour:{}\nToken name:{}\nChain:ETH\nToken Address:{}\n'.format(
                    message_header, behavious, token_name, token_address)
                show_log(message)
                send_telegram_notification(message, value, usd_value, tx['hash'], token_address)

            elif (contract_address.lower() == ETH_ROUTER_V3_ADDRESS.lower() and method_id == '0xdb3e2198') or (
                    contract_address.lower() == ETH_ROUTER_V3_1_ADDRESS.lower() and method_id == '0x5ae401dc') or (
                    contract_address.lower() == ETH_ROUTER_V3_2_ADDRESS.lower() and method_id == '0x3593564c'):
                try:
                    eth_usd_price = get_eth_price()
                except:
                    print("Because of api server, we are using old price")

                usd_value = value * eth_usd_price

                # buy function
                try:
                    if method_id == '0x3593564c':
                        token1_address, token2_address = get_tokens_inch_v3(input)
                    else:
                        token1_address, token2_address = get_tokens_v3(input)
                    token1_name = get_tokensymbol(token1_address)
                    token2_name = get_tokensymbol(token2_address)
                    # buy function
                    if token1_name == "WETH":
                        token_name = token2_name
                        token_address = token1_address
                    # sell function
                    elif token2_name == "WETH":
                        behavious = "SELL"
                        token_name = token1_name
                        token_address = token2_address
                except Exception as error:
                    show_log("Get error for {}\n{}".format(tx, error))
                    token_name = "UNKNOWN"
                    token_address = "UNKNOWN"

                message = '{}Behaviour:{}\nToken name:{}\nChain:ETH\nToken Address:{}\n'.format(
                    message_header, behavious, token_name, token_address)
                show_log(message)
                send_telegram_notification(message, value, usd_value, tx['hash'], token_address)
        latest_tx_hashes = add_item(latest_tx_hashes, tx_hash, int(tx['blockNumber']))
        # latest_tx_hashes[tx_hash] = int(tx['blockNumber'])
    return True


# Define some helper functions
def get_wallet_transactions(wallet_address):
    # api plan is 5 calls / second
    try:
        url = f'https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock={last_block_eth_number}&endblock=99999999&sort=desc&apikey={ETH_API_KEY}'
        time.sleep(0.5)
        response = requests.get(url)
        response_text = response.text
        data = json.loads(response_text)

        result = data.get('result', [])
        if not isinstance(result, list):
            show_log(
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error fetching transactions for {wallet_address} on ETH blockchain: {data}")
            return []

        return result
    except Exception as error:
        print(error)
        return []


def get_current_block_number():
    # Get ETH block number
    url = f'https://api.etherscan.io/api?module=proxy&action=eth_blockNumber&apikey={ETH_API_KEY}'
    response = requests.get(url)
    data = json.loads(response.text)
    result = data.get('result', [])
    global last_block_eth_number


def monitor_wallets():
    global eth_usd_price
    file_path = "log/watched_wallets.txt"
    if not os.path.exists(file_path):
        open(file_path, 'w').close()

    global latest_tx_hashes
    global last_run_time

    latest_tx_hashes_path = "log/latest_tx_hashes.json"
    if os.path.exists(latest_tx_hashes_path):
        with open(latest_tx_hashes_path, "r") as f:
            latest_tx_hashes = json.load(f)

    last_run_time_path = "log/last_run_time.txt"
    if os.path.exists(last_run_time_path):
        with open(last_run_time_path, "r") as f:
            last_run_time = int(f.read())
    eth_usd_price = get_eth_price()
    while True:
        try:
            # Read from file
            with open(file_path, 'r') as f:
                watched_wallets = set(f.read().splitlines())

                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(wallet_check, wallet) for wallet in watched_wallets]

                # wait for all tasks to complete
                for future in concurrent.futures.as_completed(futures):
                    future.result()

            # Save latest_tx_hashes to file
            with open(latest_tx_hashes_path, "w") as f:
                json.dump(latest_tx_hashes, f)

            # Update last_run_time
            last_run_time = int(time.time())
            with open(last_run_time_path, "w") as f:
                f.write(str(last_run_time - 150))

            # Sleep for 10 seconds
            time.sleep(30)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno, e)
            time.sleep(10)


def add_wallet(wallet_address, blockchain, rate=""):
    file_path = "log/watched_wallets.txt"
    with open(file_path, 'a') as f:
        if rate:
            f.write(f'{blockchain}:{wallet_address}:{rate}\n')
        else:
            f.write(f'{blockchain}:{wallet_address}\n')


def remove_wallet(wallet_address, blockchain):
    file_path = "log/watched_wallets.txt"
    temp_file_path = "temp.txt"
    with open(file_path, 'r') as f, open(temp_file_path, 'w') as temp_f:
        for line in f:
            if not (f'{blockchain}:{wallet_address}' in line.strip()):
                temp_f.write(line)
    os.replace(temp_file_path, file_path)


# Define the command handlers for the Telegram bot
def start(update, context):
    message = """
    👋 Welcome to the Ethereum and Binance Wallet Monitoring Bot!

    Use /add <blockchain> <wallet_address> to add a new wallet to monitor.

    Example: /add ETH 0x123456789abcdef

    Use /remove <blockchain> <wallet_address> to stop monitoring a wallet.

    Example: /remove ETH 0x123456789abcdef

    Use /list <blockchain> to list all wallets being monitored for a specific blockchain.

    Example: /list ETH or just /list

    Don't forget to star my Github repo if you find this bot useful! https://github.com/cankatx/crypto-wallet-tracker ⭐️
        """
    context.bot.send_message(chat_id=update.message.chat_id, text=message)


def add(update, context):
    if len(context.args) < 2:
        context.bot.send_message(chat_id=update.message.chat_id,
                                 text="Please provide a blockchain and wallet address to add.")
        return

    blockchain = context.args[0].lower()
    wallet_address = context.args[1]

    if len(context.args) == 3:
        rate = context.args[2]
    else:
        rate = "0"

    # Check if the wallet address is in the correct format for the specified blockchain
    if not re.match(r'^0x[a-fA-F0-9]{40}$', wallet_address):
        context.bot.send_message(chat_id=update.message.chat_id,
                                 text=f"{wallet_address} is not a valid Ethereum wallet address.")
        return

    add_wallet(wallet_address, blockchain, rate)
    message = f'Added {wallet_address} to the list of watched {blockchain.upper()} wallets.'
    context.bot.send_message(chat_id=update.message.chat_id, text=message)


def remove(update, context):
    if len(context.args) < 2:
        context.bot.send_message(chat_id=update.message.chat_id,
                                 text="Please provide a blockchain and wallet address to remove.\nUsage: /remove ARB 0x123456789abcdef")
        return
    blockchain = context.args[0].lower()
    wallet_address = context.args[1]
    remove_wallet(wallet_address, blockchain)
    message = f'Removed {wallet_address} from the list of watched {blockchain.upper()} wallets.'
    context.bot.send_message(chat_id=update.message.chat_id, text=message)


def list_wallets(update, context):
    with open("log/watched_wallets.txt", "r") as f:
        wallets = [line.strip() for line in f.readlines()]
    if wallets:
        eth_wallets = []
        bsc_wallets = []
        arb_wallets = []
        for wallet in wallets:
            try:
                blockchain, wallet_address, rate = wallet.split(':')
            except:
                blockchain, wallet_address = wallet.split(':')
                rate = ""
            if blockchain == 'eth':
                eth_wallets.append([wallet_address, rate])
            elif blockchain == 'bsc':
                bsc_wallets.append([wallet_address, rate])
            elif blockchain == 'arb':
                arb_wallets.append([wallet_address, rate])

        message = "The following wallets are currently being monitored\n"
        message += "\n"
        if eth_wallets:
            message += "Ethereum Wallets:\n"
            for i, wallet in enumerate(eth_wallets):
                if wallet[1]:
                    message += f"{i + 1}. {wallet[0]}:{wallet[1]}\n"
                else:
                    message += f"{i + 1}. {wallet[0]}\n"
            message += "\n"
        if bsc_wallets:
            message += "Binance Coin Wallets:\n"
            if wallet[1]:
                message += f"{i + 1}. {wallet[0]}:{wallet[1]}\n"
            else:
                message += f"{i + 1}. {wallet[0]}\n"
        if arb_wallets:
            message += "ARBITRAM Wallets:\n"
            if wallet[1]:
                message += f"{i + 1}. {wallet[0]}:{wallet[1]}\n"
            else:
                message += f"{i + 1}. {wallet[0]}\n"
            message += "\n"
        context.bot.send_message(chat_id=update.message.chat_id, text=message)
    else:
        message = "There are no wallets currently being monitored."
        context.bot.send_message(chat_id=update.message.chat_id, text=message)


# # Set up the Telegram bot
# from telegram.ext import Updater, CommandHandler
#
# updater = Updater(token=TELEGRAM_BOT_TOKEN, use_context=True)
# dispatcher = updater.dispatcher
#
# # Define the command handlers
# start_handler = CommandHandler('start', start)
# add_handler = CommandHandler('add', add)
# remove_handler = CommandHandler('remove', remove)
# list_handler = CommandHandler('list', list_wallets)
#
# # Add the command handlers to the dispatcher
# dispatcher.add_handler(start_handler)
# dispatcher.add_handler(add_handler)
# dispatcher.add_handler(remove_handler)
# dispatcher.add_handler(list_handler)

# updater.start_polling()
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Telegram bot started.")
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Monitoring wallets...")
monitor_wallets()

from web3 import Web3
import json
import requests
import time
import logging.config

# Update the following variables with your own Etherscan and BscScan API keys and Telegram bot token
TELEGRAM_BOT_TOKEN = '6231834333:AAGjSS19_cTpaJacT5tn8P267_u5Ot0Ut2k'
TELEGRAM_CHAT_ID = '-896605162'
JSON_COUNT_LIMIT = 100

# ETHEREUM
ETH_API_KEY = 'P4R8Y1J1G7B49HRR9WG9T3MDKV35T3Y6T5'
ETH_ROUTER_ADDRESS = '0x7a250d5630b4cf539739df2c5dacb4c659f2488d'
ETH_ROUTER_V3_ADDRESS = '0xe592427a0aece92de3edee1f18e0157c05861564'
ETH_ROUTER_V3_1_ADDRESS = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'
ETH_ROUTER_V3_2_ADDRESS = '0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b'
ETH_USDT_ADDRESS = '0xdac17f958d2ee523a2206206994597c13d831ec7'
ETH_WETH_ADDRESS = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2'
ETH_RPC = 'https://twopaws.io/rpc'
eth_w3 = Web3(Web3.HTTPProvider(ETH_RPC))
eth_router = Web3.to_checksum_address(ETH_ROUTER_ADDRESS)
eth_usdt = Web3.to_checksum_address(ETH_USDT_ADDRESS)
eth_weth = Web3.to_checksum_address(ETH_WETH_ADDRESS)

Round = lambda x, n: float(
    eval('"%.' + str(int(n)) + 'f" % ' + repr(int(x) + round(float('.' + str(float(x)).split('.')[1]), n))))

eth_abi = ''
with open('abi/abi.json', 'r') as f:
    eth_abi = json.load(f)

router_abi = ''
with open('abi/router.json', 'r') as f:
    router_abi = json.load(f)
logging.config.dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "default",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "class": "logging.FileHandler",
            "level": "INFO",
            "formatter": "default",
            "filename": "bot.log",
            "mode": "a",
            "encoding": "utf-8"
        }
    },
    "root": {
        "level": "INFO",
        "handlers": [
            "console",
            "file"
        ]
    }
})
LOGGER = logging.getLogger()
def show_log(msg):
    LOGGER.info(msg)

def add_item(data, tx,blocknumber):
    # Check the count of items
    if len(data) >= JSON_COUNT_LIMIT:
        # Get the first added item
        first_item = next(iter(data))
        # Remove the first item from the dictionary
        del data[first_item]

    # Add the new item to the dictionary
    data[tx] = blocknumber
    return data
def send_telegram_notification(message, value, usd_value, tx_hash,address):
    etherscan_link = f'<a href="https://etherscan.io/tx/{tx_hash}">Etherscan</a>'
    dexscan_link = f'<a href="https://dexscreener.com/ethereum/{address}">DexScanner</a>'

    # url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    # payload = {'chat_id': f'{TELEGRAM_CHAT_ID}',
    #            'text': f'{message}\n TX : {etherscan_link}\n DexScan:{dexscan_link}\nValue: {value:.6f} (${usd_value:.2f})',
    #            'parse_mode': 'HTML'}
    #
    # response = requests.post(url, data=payload)
    print(
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Telegram notification sent with message: {message}, value: {value} (${usd_value:.2f})")
    # return response


def get_tokensymbol(token_address):
    try:
        token_address = Web3.to_checksum_address(token_address)
        token_contract = eth_w3.eth.contract(address=token_address, abi=eth_abi)
        token_name = token_contract.functions.symbol().call()
    except:
        token_name = ""
    return token_name


def get_eth_price():
    router_contract = eth_w3.eth.contract(address=eth_router, abi=router_abi)
    oneToken = eth_w3.to_wei(1, 'Ether')
    price = router_contract.functions.getAmountsOut(oneToken,
                                                    [eth_weth, eth_usdt]).call()
    return Round((price[1]) / 10 ** 6, 2)


def get_tokens_v3(input):
    BUYMETHOD = "472b43f3"
    SELLMETHOD = "42712a67"

    index = input.find(BUYMETHOD)
    try:
        if index != -1:
            tokenA = input[index + 8 + 64 * 5 + 24:index + 8 + 64 * 6]
            tokenB = input[index + 8 + 64 * 6 + 24:index + 8 + 64 * 7]
            return tokenA, tokenB
        else:
            index = input.find(SELLMETHOD)
            if index != -1:
                tokenB = input[index + 8 + 64 * 5 + 24:index + 8 + 64 * 6]
                tokenA = input[index + 8 + 64 * 6 + 24:index + 8 + 64 * 7]
                return tokenA, tokenB
    except:
        pass
    return "", ""


def get_tokens_inch_v3(input):
    BUYMETHOD = "0b000c"
    SELLMETHOD = "0a000c04"

    index = input.find(BUYMETHOD)
    try:
        if index != -1:
            tokenA = input[index + 64 * 15:index + 64 * 15 + 40]
            tokenB = input[index + 64 * 15 + 46:index + 64 * 16 + 22]
            return tokenA, tokenB
        else:
            index = input.find(SELLMETHOD)
            if index != -1:
                tokenA = input[index + 64 * 7 + 24:index + 64 * 8]
                tokenB = input[index + 64 * 25 + 46:index + 64 * 26 + 22]
                return tokenA, tokenB
    except:
        pass
    return "", ""

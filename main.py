from htutil import file
import requests
import re
import logging
import time
from pathlib import Path
from requests.auth import HTTPBasicAuth
import oss2
from message_pusher_sdk.message_pusher_sdk import MessagePusherSDK

cfg = file.read_json('config.json')


logging.basicConfig(format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.INFO)


pattern = re.compile(r'\((.*?)\)')

host = cfg['host']

session = requests.Session()
if cfg['auth']:
    session.auth = HTTPBasicAuth(
        cfg['auth']['username'], cfg['auth']['password'])
session.proxies = {'http': '', 'https': ''}

oss_enabled = cfg['oss'] and cfg['oss']['enabled']

alert_enabled = cfg['alert'] and cfg['alert']['enabled']

if oss_enabled:
    bucket = oss2.Bucket(oss2.Auth( cfg['oss']['access_key_id'],  cfg['oss']['access_key_secret']), cfg['oss']['endpoint'],  cfg['oss']['bucket_name'])
if alert_enabled:
    sdk = MessagePusherSDK(cfg['alert']['host'], cfg['alert']['token'])

def alert(description: str):
    if alert_enabled:
        resp = sdk.push(cfg['alert']['username'], '', description, '')
        if resp:
            logging.error(resp)

def get_image(name: str, _type: str) -> bool:
    p = Path('data') / _type
    if not p.exists():
        p.mkdir(parents=True)

    prompt = f'#{name}{_type}'
    path = p / f'{name}.jpg'
    # path = f'{name}-{_type}.jpg'

    resp = session.post(f'{host}/api/chat-process', json={
        "prompt": prompt
    }, ).text

    match = pattern.search(resp)
    if not match:
        logging.info(f"img not found, resp = {resp}")
        return False
    else:
        img_url = f'{host}/{match.group(1)}'
        resp = session.get(img_url)
        with open(path, 'wb') as f:
            f.write(resp.content)

        if oss_enabled:
            bucket.put_object(f'{name}-{_type}.jpg', resp.content)

        return True


resp = session.post(f'{host}/api/chat-process', json={
    "prompt": "#更新面板"
})

if resp.status_code != 200:
    logging.info('#更新面板 fail, resp =', resp)
else:
    logging.info('#更新面板 success')

time.sleep(2)

fail_names = []

for name in cfg['names']:
    for _type in ['面板', '圣遗物']:
        logging.info(f'{name} {_type}')
        r = get_image(name, _type)
        if not r:
            fail_names.append(name)
        time.sleep(2)

if fail_names:
    logging.info('fail_names =', fail_names)
    alert(f'yunzai-bot-script failed, names = {fail_names}')
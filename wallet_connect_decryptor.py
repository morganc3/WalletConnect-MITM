from mitmproxy import ctx, http, command, contentviews
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import json
import os
import secrets

def hex_to_bytes(hex_string):
    return bytes(bytearray.fromhex(hex_string))

class WalletConnectEncryption:
    def __init__(self, key, message='', iv=''):
        self.key = hex_to_bytes(key)
        if message:
            obj = json.loads(message)
            payload_str = obj.get('payload')
            payload = json.loads(payload_str)
            self.iv = hex_to_bytes(payload.get('iv'))
        if iv:
            self.iv = hex_to_bytes(iv)

    def encrypt(self, message):
        message = bytes(message, 'utf-8')
        if len(message) % 16 != 0:
            padding_count = 16 - len(message) % 16
            for i in range(padding_count):
                message += padding_count.to_bytes(1, byteorder='big')
        obj = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = obj.encrypt(message).hex()
        return ciphertext

    def decrypt(self, ciphertext):
        obj = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = hex_to_bytes(ciphertext)
        message = obj.decrypt(ciphertext)
        last_byte = message[len(message)-1]
        return message[:len(message)-last_byte] # remove padding

    def decrypt_from_ws_message(self, message):
        obj = json.loads(message)
        payload_str = obj.get('payload')
        payload = json.loads(payload_str)
        ciphertext = payload.get('data')
        plain = self.decrypt(ciphertext)
        return plain

    # re-encrypts message with a new payload value and computes the correct hmac
    def update_message_with_new_payload(self, message, new_payload_data):
        msg = json.loads(message)
        new_payload_data = json.dumps(new_payload_data, separators=(',', ':'))
        old_payload = msg['payload']
        old_payload = json.loads(old_payload)
        new_payload = old_payload
        new_payload['data'] = self.encrypt(new_payload_data)
        new_hmac = self.hmac(new_payload['data'])
        new_payload['hmac'] = new_hmac
        new_payload['iv'] = self.iv.hex()
        msg['payload'] = json.dumps(new_payload, separators=(',', ':'))
        msg['silent'] = False
        ctx.log.info(msg)
        return json.dumps(msg, separators=(',', ':'))

    def hmac(self, ciphertext):
        h = HMAC.new(self.key, digestmod=SHA256)
        h.update(hex_to_bytes(ciphertext)+self.iv)
        return h.hexdigest()


key = ""
client_topic = ""
server_topic = ""

def get_cached_item(item):
    f = open(os.path.expanduser(f'~/.mitmproxy/{item}'), "r")
    item_val = f.read()
    f.close()
    return item_val

def websocket_message(flow: http.HTTPFlow):
    global key
    global wc_flow # latest websocket flow connection
    global client_topic
    global server_topic
    if not key:
        # key not set yet, check file
        try:
            key = get_cached_item('wc_key')
        except:
            ctx.log.warn("wc key not set")

    assert flow.websocket is not None  # make type checker happy
    # get the latest message
    message = flow.websocket.messages[-1]

    try:
        msg_json = json.loads(message.content)
    except:
        return
    
    if not msg_json.get('payload'):
        return
    try:
        payload = json.loads(msg_json.get('payload'))
    except:
        return
    
    if msg_json.get('topic'):
        if message.from_client:
            client_topic = msg_json.get('topic')
        else:
            server_topic = msg_json.get('topic')
    else:
        ctx.log.error('message is missing topic')
        return
    
    wc_flow = flow
    ciphertext = payload.get('data')
    iv = payload.get('iv')

    if not iv or not ciphertext:
        return
    wce = WalletConnectEncryption(key, message=message.content)
    plaintext_payload = wce.decrypt_from_ws_message(message.content)
    # was the message sent from the client or server?
    if message.from_client:
        ctx.log.info(f"Client sent a message: {plaintext_payload!r}")
    else:
        ctx.log.info(f"Server sent a message: {plaintext_payload!r}")


@command.command("wc_set_key")
def wc_set_key(
    key_in: str
) -> None:
    '''
        Set AES encryption key to use to encrypt and decrypt messages. 
        This is the "key" parameter in the WC URL
    '''
    global key
    key = key_in
    f = open(os.path.expanduser('~/.mitmproxy/wc_key'), "w")
    f.write(key_in)
    f.close()


@command.command("wc_send")
def wc_send(path: str, to_client: bool):
    '''
        Send an encrypted message either to client or to server
    '''
    global wc_flow
    global key
    global client_topic
    global server_topic
    if not wc_flow:
        ctx.log.error("no active WC websocket connection")
        return

    if not key:
    # key not set yet, check file
        try:
            key = get_cached_item('wc_key')
        except:
            ctx.log.error("wc key not set")

    if not (client_topic and to_client) and not (server_topic and not to_client):
        ctx.log.error("wc topic not set")

    # random IV
    wce = WalletConnectEncryption(key, iv=secrets.token_hex(16))
    topic = client_topic if to_client else server_topic
    msg_template = r'{"topic":"'+topic+r'","type":"pub","payload":"{}"}'
    new_payload = json.loads(open(path, 'r').read())

    json.loads(msg_template)
    # 3rd argument is to_client bool. Topic seems to be different between client and server
    new_msg = wce.update_message_with_new_payload(msg_template, new_payload)
    ctx.master.commands.call("inject.websocket", wc_flow, False, new_msg.encode())


class ViewSwapCase(contentviews.View):
    name = "wallet_connect_decrypted"
    content_types = ["text/plain"]

    def __call__(self, data, **metadata) -> contentviews.TViewResult:
        wce = WalletConnectEncryption(key, message=data)
        plaintext_payload = wce.decrypt_from_ws_message(data)
        return "decrypted message", contentviews.format_text(plaintext_payload)


view = ViewSwapCase()


def load(l):
    contentviews.add(view)


def done():
    contentviews.remove(view)
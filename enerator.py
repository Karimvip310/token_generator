import hmac
import hashlib
import requests
import string
import random
import time
import re
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import string
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def guest_generate():
    locale = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
    country = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
    device = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    android_ver = f"{random.randint(8, 13)}.{random.randint(0, 5)}"
    
    hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
    key = bytes.fromhex(hex_key)
    
    random_string = ''.join(random.choice(string.ascii_letters) for _ in range(8))
    random_number = random.randint(1000, 9999)
    timestamp = str(int(time.time() * 1000))
    combined = f"{random_string}{random_number}{timestamp}"
    password = hashlib.sha256(combined.encode('utf-8')).hexdigest().upper()
    
    data = {
        "app_id": 100067,
        "client_type": 2,
        "password": password,
        "source": 2
    }
    
    json_data = json.dumps(data)
    signature = hmac.new(key, json_data.encode('utf-8'), hashlib.sha256).hexdigest()
    
    url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
    
    headers = {
        "User-Agent": f"GarenaMSDK/4.0.39({device} ;Android {android_ver};{locale};{country};)",
        "Authorization": "Signature " + signature,
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Host": "100067.connect.garena.com"
    }
    
    response = requests.post(url, headers=headers, data=json_data)
    
    if response.status_code == 200:
        response_data = response.json()
        if response_data.get("code") == 0:
            uid = response_data.get("data", {}).get("uid")
            return uid, password
    
    return None, password

def guest_token(uid, password):
    locale = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
    country = ''.join(random.choice(string.ascii_lowercase) for _ in range(2))
    device = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    android_ver = f"{random.randint(8, 13)}.{random.randint(0, 5)}"
    
    url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "100067.connect.garena.com",
        "User-Agent": f"GarenaMSDK/4.0.39({device} ;Android {android_ver};{locale};{country};)"
    }
    
    data = {
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2,
        "password": password,
        "response_type": "token",
        "uid": uid
    }
    
    json_data = json.dumps(data)
    response = requests.post(url, headers=headers, data=json_data)
    
    if response.status_code == 200:
        response_data = response.json()
        if response_data.get("code") == 0:
            data_info = response_data.get("data", {})
            NEW_ACCESS_TOKEN = data_info.get('access_token')
            NEW_OPEN_ID = data_info.get('open_id')
            return NEW_ACCESS_TOKEN, NEW_OPEN_ID
    
    return None, None
    
def encode_string(original):
    keystream = [
        0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
        0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30
    ]
    encoded = ""
    for i in range(len(original)):
        orig_byte = ord(original[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return encoded
    
def create_protobuf_packet(fields):
    packet = bytearray()

    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            field_header = (field << 3) | 2
            encoded_value = nested_packet
            length_bytes = bytearray()
            length = len(encoded_value)
            while True:
                b = length & 0x7F
                length >>= 7
                if length:
                    b |= 0x80
                length_bytes.append(b)
                if not length:
                    break
            packet.extend(bytearray([field_header]))
            packet.extend(length_bytes)
            packet.extend(encoded_value)

        elif isinstance(value, int):
            field_header = (field << 3) | 0
            value_bytes = bytearray()
            n = value
            while True:
                b = n & 0x7F
                n >>= 7
                if n:
                    b |= 0x80
                value_bytes.append(b)
                if not n:
                    break
            packet.extend(bytearray([field_header]))
            packet.extend(value_bytes)

        elif isinstance(value, str) or isinstance(value, bytes):
            field_header = (field << 3) | 2
            encoded_value = value.encode() if isinstance(value, str) else value
            length_bytes = bytearray()
            length = len(encoded_value)
            while True:
                b = length & 0x7F
                length >>= 7
                if length:
                    b |= 0x80
                length_bytes.append(b)
                if not length:
                    break
            packet.extend(bytearray([field_header]))
            packet.extend(length_bytes)
            packet.extend(encoded_value)

    return packet
    
def parse_protobuf(data, index=0, end=None):
    if end is None:
        end = len(data)
    result = {}

    while index < end:
        shift = 0
        key = 0
        while True:
            b = data[index]
            index += 1
            key |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7

        field_number = key >> 3
        wire_type = key & 0x07

        if wire_type == 0:
            shift = 0
            value = 0
            while True:
                b = data[index]
                index += 1
                value |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            result[str(field_number)] = {'wire_type': 'varint', 'data': value}

        elif wire_type == 2:
            shift = 0
            length = 0
            while True:
                b = data[index]
                index += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            raw_value = data[index:index+length]
            index += length

            if str(field_number) in ('22', '23'):
                value = raw_value
            else:
                try:
                    nested = parse_protobuf(raw_value, 0, len(raw_value))
                    value = nested if nested else raw_value
                except:
                    value = raw_value
            result[str(field_number)] = {'wire_type': 'string' if isinstance(value, str) else 'length_delimited', 'data': value}

        elif wire_type == 5:
            value = int.from_bytes(data[index:index+4], 'little')
            index += 4
            result[str(field_number)] = {'wire_type': '32bit', 'data': value}

        elif wire_type == 1:
            value = int.from_bytes(data[index:index+8], 'little')
            index += 8
            result[str(field_number)] = {'wire_type': '64bit', 'data': value}

        else:
            raise NotImplementedError(f"Wire type {wire_type} not implemented")

    return result
    
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()    
    
def generate_random_name():
    timestamp = str(int(time.time() * 1000))
    hex_time = hex(int(timestamp))[2:]
    xor_name = ''
    for c in hex_time:
        rand_char = random.choice(string.ascii_lowercase)
        xor_c = chr(ord(c) ^ ord(rand_char))
        xor_name += xor_c if xor_c.isalnum() else random.choice(string.ascii_lowercase)
    if len(xor_name) < 12:
        xor_name += ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12 - len(xor_name)))
    return xor_name[:12]
    
def get_jwt(NEW_ACCESS_TOKEN, NEW_OPEN_ID):
    PAYLOAD = b':\x071.120.1\xaa\x01\x02zb\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014\xca\x03 7428b253defc164018c604a1ebbfebdf'
    PAYLOAD = PAYLOAD.replace(
        b"6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae",
        NEW_ACCESS_TOKEN.encode("UTF-8")
    )
    PAYLOAD = PAYLOAD.replace(
        b"55ed759fcf94f85813e57b2ec8492f5c",
        NEW_OPEN_ID.encode("UTF-8")
    )
    PAYLOAD = PAYLOAD.hex()
    PAYLOAD = encrypt_api(PAYLOAD)
    PAYLOAD = bytes.fromhex(PAYLOAD)

    URL = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB52",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer",
        "Content-Length": str(len(PAYLOAD.hex())),
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)",
        "Host": "loginbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    r = requests.post(URL, headers=headers, data=PAYLOAD, verify=False) 
    if r.status_code == 200:
    	hex_data = r.content.hex()
    	data_bytes = bytes.fromhex(hex_data)
    	decoded = parse_protobuf(data_bytes)
    	return decoded.get("8", {}).get('data').decode('utf-8')
    	
def get_jwt2(NEW_ACCESS_TOKEN, NEW_OPEN_ID):
    PAYLOAD = b':\x071.120.1\xaa\x01\x02zb\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014\xca\x03 7428b253defc164018c604a1ebbfebdf'
    PAYLOAD = PAYLOAD.replace(
        b"6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae",
        NEW_ACCESS_TOKEN.encode("UTF-8")
    )
    PAYLOAD = PAYLOAD.replace(
        b"55ed759fcf94f85813e57b2ec8492f5c",
        NEW_OPEN_ID.encode("UTF-8")
    )
    PAYLOAD = PAYLOAD.hex()
    PAYLOAD = encrypt_api(PAYLOAD)
    PAYLOAD = bytes.fromhex(PAYLOAD)

    URL = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB52",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Bearer",
        "Content-Length": str(len(PAYLOAD.hex())),
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)",
        "Host": "loginbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    r = requests.post(URL, headers=headers, data=PAYLOAD, verify=False) 
    if r.status_code == 200:
    	hex_data = r.content.hex()
    	data_bytes = bytes.fromhex(hex_data)
    	decoded = parse_protobuf(data_bytes)
    	return decoded.get("8", {}).get('data').decode('utf-8'),decoded.get("10", {}).get('data').decode('utf-8'),PAYLOAD
    	
def chooseregion(rg, jwt_token):
    url = "https://loginbp.ggblueshark.com/ChooseRegion"
    
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB52"
    }

    fields = {1: str(rg)}
    packet = create_protobuf_packet(fields).hex()
    payload_decrypted = bytes.fromhex(packet)
    payload = bytes.fromhex(encrypt_api(payload_decrypted.hex()))

    response = requests.post(url, headers=headers, data=payload)
    return response

def register_account(access, open_id, region):
    url = "https://loginbp.ggblueshark.com/MajorRegister"
    headers = {
        "Expect": "100-continue",
        "Authorization": "Bearer",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB52",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; ASUS_Z01QD Build/V417IR)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    fields = {
        1: generate_random_name(),
        2: access,
        3: open_id,
        5: 102000007,
        6: 4,
        7: 1,
        13: 1,
        14: encode_string(open_id),
        15: 1,
        16: 1,
        17: 1
    }
    packet = create_protobuf_packet(fields).hex()
    payload_decrypted = bytes.fromhex(packet)
    payload = bytes.fromhex(encrypt_api(payload_decrypted.hex()))

    response = requests.post(url, headers=headers, data=payload)
    return response
    
def active_account(jwt,link, pl):
    url = link + "/GetLoginData"
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB52",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br"
    }

    response = requests.post(url, headers=headers, data=pl, verify=False)
    return response    

file_name = "accs.json"

if os.path.exists(file_name):
    with open(file_name, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except:
            data = {}
else:
    data = {}

created = 0

while created < 300:
    try:
        rg = "me".upper()
        uid, password = guest_generate()
        access, open_id = guest_token(uid, password)

        res = register_account(access, open_id, rg)
        if res.status_code != 200:
            raise Exception()

        jwt = get_jwt(access, open_id)
        r = chooseregion(rg, jwt)
        if r.status_code != 200:
            raise Exception()

        jwt, link, payload = get_jwt2(access, open_id)
        res_active = active_account(jwt, link, payload)
        if res_active.status_code != 200:
            raise Exception()

        print("تم صنع حسابك")
        print(uid)
        print(password)

        data[str(uid)] = password

        with open(file_name, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        created += 1
        time.sleep(0.5)

    except:
        print("حدث خطأ... إعادة المحاولة بعد 5 ثواني")
        time.sleep(5)

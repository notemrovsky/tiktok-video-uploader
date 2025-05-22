import hashlib
import hmac
import json
import uuid
import zlib
from datetime import datetime, UTC
from typing import Dict, List, Any, Optional
from urllib.parse import quote

import curl_cffi.requests
import random_strings
import structlog

logger = structlog.get_logger()


def get_signing_key(secret_access_key: str, date: str, region: str, service: str) -> bytes:
    key = f"AWS4{secret_access_key}".encode('utf-8')
    date_key = hmac.new(key, date.encode('utf-8'), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode('utf-8'), hashlib.sha256).digest()
    service_key = hmac.new(region_key, service.encode('utf-8'), hashlib.sha256).digest()
    signing_key = hmac.new(service_key, "aws4_request".encode('utf-8'), hashlib.sha256).digest()
    return signing_key


def encode_query_params(params: Dict[str, Any]) -> str:
    result = []
    for key in sorted(params.keys()):
        value = params[key]
        if value is None:
            continue
        
        encoded_key = quote(str(key))
        if encoded_key:
            if isinstance(value, list):
                result.append(f"{encoded_key}={quote('&' + encoded_key + '=').join(sorted(map(quote, map(str, value))))}")
            else:
                result.append(f"{encoded_key}={quote(str(value))}")
    
    return "&".join(filter(None, result))


def is_signable_header(header: str) -> bool:
    return header.lower().startswith("x-amz-") or header not in [
        "authorization", "content-type", "content-length", "user-agent", 
        "presigned-expires", "expect", "x-amzn-trace-id"
    ]


def canonical_header_values(value: str) -> str:
    return " ".join(value.split()).strip()


def canonical_headers(headers: Dict[str, str]) -> str:
    header_list = [[key, headers[key]] for key in headers]
    header_list.sort(key=lambda x: x[0].lower())
    
    canonical = []
    for header in header_list:
        key = header[0].lower()
        if is_signable_header(key):
            value = header[1]
            if value is None or not hasattr(value, "__str__"):
                raise Exception(f"Header {key} contains invalid value")
            canonical.append(f"{key}:{canonical_header_values(str(value))}")
    
    return "\n".join(canonical)


def signed_headers(headers: Dict[str, str]) -> str:
    signed = []
    for key in headers:
        key_lower = key.lower()
        if is_signable_header(key_lower):
            signed.append(key_lower)
    
    signed.sort()
    return ";".join(signed)


def canonical_string(endpoint: str, http_method: str, request_params: Dict[str, Any], 
                    request_headers: Dict[str, str], request_body: str = "") -> str:
    elements = [
        http_method.upper(),
        endpoint,
        encode_query_params(request_params),
        canonical_headers(request_headers) + "\n",
        signed_headers(request_headers),
        hashlib.sha256(request_body.encode()).hexdigest()
    ]
    return "\n".join(elements)


def string_to_sign(secret_access_key: str, endpoint: str, http_method: str, 
                  request_params: Dict[str, Any], request_headers: Dict[str, str], 
                  request_body: str = "") -> str:
    amz_date = request_headers["X-Amz-Date"]
    string_parts = [
        "AWS4-HMAC-SHA256",
        amz_date,
        f'{amz_date[:8]}/US-TTP/vod/aws4_request',
        hashlib.sha256(canonical_string(endpoint, http_method, request_params, request_headers, request_body).encode()).hexdigest()
    ]
    string_to_sign_value = "\n".join(string_parts)
    
    signing_key = get_signing_key(secret_access_key, amz_date[:8], "US-TTP", "vod")
    signature = hmac.new(signing_key, string_to_sign_value.encode(), hashlib.sha256).digest().hex()
    return signature


def iso8601_no_separators() -> str:
    timestamp = datetime.now(UTC)
    iso_time = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return iso_time.replace(":", "").replace("-", "")


def load_cookies(json_file_path: str) -> Dict[str, str]:
    with open(json_file_path, 'r') as f:
        cookies_data = json.load(f)
    
    formatted_cookies = {}
    for cookie in cookies_data:
        name = cookie.get('name')
        value = cookie.get('value')
        if name and value:
            formatted_cookies[name] = value
    
    return formatted_cookies


def calculate_crc32(content: bytes) -> str:
    prev = 0
    prev = zlib.crc32(content, prev)
    return ("%X" % (prev & 0xFFFFFFFF)).lower().zfill(8)


class TikTokUploader:
    def __init__(self, cookie_file: str) -> None:
        self.session = curl_cffi.requests.Session(impersonate="chrome133a")
        self.session.headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.7',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://www.tiktok.com/tiktokstudio/upload?from=creator_center',
            'sec-ch-ua': '"Not(A:Brand";v="99", "Brave";v="133", "Chromium";v="133"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
        }
        self.session.cookies.update(load_cookies(cookie_file))
    
    def upload_video(self, video_path: str, video_description: str) -> Optional[str]:
        try:
            params = {'aid': '1988'}
            response = self.session.get('https://www.tiktok.com/api/v1/video/upload/auth/', params=params)
            auth_data = response.json()["video_token_v5"]
            
            secret_key = auth_data["secret_acess_key"]
            session_token = auth_data["session_token"]
            access_key_id = auth_data["access_key_id"]
            timestamp = iso8601_no_separators()

            with open(video_path, "rb") as f:
                video_content = f.read()
            
            file_size = len(video_content)
            random_string = random_strings.random_string(11).lower()

            signature = string_to_sign(
                secret_key, '/top/v1', 'get',
                {
                    'Action': 'ApplyUploadInner',
                    'Version': '2020-11-19',
                    'SpaceName': 'tiktok',
                    'FileType': 'video',
                    'IsInner': '1',
                    'ClientBestHosts': 'tos19-up-useast5.tiktokcdn-us.com,tos16-up-useast5.tiktokcdn-us.com',
                    'FileSize': str(file_size),
                    'X-Amz-Expires': '604800',
                    's': random_string,
                    'device_platform': 'web',
                },
                {
                    "X-Amz-Date": timestamp,
                    "x-amz-security-token": session_token
                }
            )

            self.session.headers.update({
                'authorization': f'AWS4-HMAC-SHA256 Credential={access_key_id}/{timestamp[:8]}/US-TTP/vod/aws4_request, SignedHeaders=x-amz-date;x-amz-security-token, Signature={signature}',
                'x-amz-date': timestamp,
                'x-amz-security-token': session_token,
            })

            upload_params = {
                'Action': 'ApplyUploadInner',
                'Version': '2020-11-19',
                'SpaceName': 'tiktok',
                'FileType': 'video',
                'IsInner': '1',
                'ClientBestHosts': 'tos19-up-useast5.tiktokcdn-us.com,tos16-up-useast5.tiktokcdn-us.com',
                'FileSize': str(file_size),
                'X-Amz-Expires': '604800',
                's': random_string,
                'device_platform': 'web',
            }

            response = self.session.get('https://www.tiktok.com/top/v1', params=upload_params)
            upload_node = response.json()["Result"]["InnerUploadAddress"]["UploadNodes"][0]
            
            video_id = upload_node["Vid"]
            store_uri = upload_node["StoreInfos"][0]["StoreUri"]
            video_auth = upload_node["StoreInfos"][0]["Auth"]
            upload_host = upload_node["UploadHost"]
            session_key = upload_node["SessionKey"]
            upload_uuid = str(uuid.uuid4())

            logger.info("Video upload started", video_id=video_id)

            user_response = self.session.get(
                'https://www.tiktok.com/tiktokstudio/api/web/user',
                params={'needIsVerified': 'true', 'needProfileBio': 'true'}
            )
            
            user_data = user_response.json()
            nickname = user_data["userBaseInfo"]["UserProfile"]["UserBase"]["NickName"]
            user_id = user_data["userId"]

            chunk_size = 5242880
            chunks = [video_content[i:i+chunk_size] for i in range(0, file_size, chunk_size)]
            crcs = []

            for i, chunk in enumerate(chunks):
                crc = calculate_crc32(chunk)
                crcs.append(crc)

                self.session.headers = {
                    "accept": "*/*",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.7",
                    "authorization": video_auth,
                    "cache-control": "no-cache",
                    "connection": "keep-alive",
                    "content-crc32": crc,
                    "content-disposition": "attachment; filename=\"undefined\"",
                    "content-length": str(len(chunk)),
                    "content-type": "application/octet-stream",
                    "host": str(upload_host),
                    "origin": "https://www.tiktok.com",
                    "pragma": "no-cache",
                    "referer": "https://www.tiktok.com/",
                    "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "Linux",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "cross-site",
                    "sec-gpc": "1",
                    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                    "x-storage-u": str(user_id)
                }

                chunk_params = {
                    "uploadid": str(upload_uuid),
                    "part_number": str(i + 1),
                    "phase": "transfer",
                    "part_offset": "0",
                    "uploadmode": "stream",
                    "enable_omit_initupload": "1",
                    "size": str(len(chunk)),
                    "offset": "0"
                }

                url = f"https://{upload_host}/upload/v1/{store_uri}"
                response = self.session.post(url, params=chunk_params, data=chunk)
                logger.debug("Video part uploaded", part=response.json()["data"]["part_number"], nickname=nickname)

            self.session.headers = {
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.7',
                'Authorization': video_auth,
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Content-Type': 'application/json',
                'Origin': 'https://www.tiktok.com',
                'Pragma': 'no-cache',
                'Referer': 'https://www.tiktok.com/',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-GPC': '1',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
                'X-Storage-U': str(user_id),
                'X-Upload-With-PostUpload': '1',
                'sec-ch-ua': '"Not(A:Brand";v="99", "Brave";v="133", "Chromium";v="133"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
            }

            finish_params = {
                'uploadmode': 'stream',
                'phase': 'finish',
                'uploadid': str(upload_uuid),
                'size': str(file_size),
            }

            finish_data = {
                'parts_crc': ','.join([f"{i+1}:{crcs[i]}" for i in range(len(crcs))]),
                'post_upload_param': {
                    'sts2_token': session_token,
                    'sts2_secret': secret_key,
                    'session_key': session_key,
                    'functions': [],
                },
            }

            response = self.session.post(
                f"https://{upload_host}/upload/v1/{store_uri}",
                params=finish_params,
                json=finish_data,
            )
            
            upload_result = response.json()["data"]["post_upload_resp"]["results"][0]
            video_duration = upload_result["video_meta"]["Duration"]
            final_video_id = upload_result["vid"]
            logger.info("Video upload completed", video_duration=video_duration, video_id=final_video_id, nickname=nickname)

            self.session.headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.7',
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'origin': 'https://www.tiktok.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.tiktok.com/tiktokstudio/upload?from=creator_center',
                'sec-ch-ua': '"Not(A:Brand";v="99", "Brave";v="133", "Chromium";v="133"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'sec-gpc': '1',
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
            }

            post_params = {
                'app_name': 'tiktok_web',
                'channel': 'tiktok_web',
                'device_platform': 'web',
                'tz_name': 'America/New_York',
                'aid': '1988',
            }

            post_data = {
                'post_common_info': {
                    'creation_id': random_strings.random_string(21),
                    'enter_post_page_from': 2,
                    'post_type': 3,
                },
                'feature_common_info_list': [
                    {
                        'geofencing_regions': [],
                        'playlist_name': '',
                        'playlist_id': '',
                        'tcm_params': '{"commerce_toggle_info":{}}',
                        'sound_exemption': 0,
                        'anchors': [],
                        'vedit_common_info': {
                            'draft': '',
                            'video_id': final_video_id,
                        },
                        'privacy_setting_info': {
                            'visibility_type': 0,
                            'allow_duet': 1,
                            'allow_stitch': 1,
                            'allow_comment': 1,
                        },
                        'content_check_id': '',
                    },
                ],
                'single_post_req_list': [
                    {
                        'batch_index': 0,
                        'video_id': final_video_id,
                        'is_long_video': 0,
                        'single_post_feature_info': {
                            'text': video_description,
                            'text_extra': [],
                            'markup_text': video_description,
                            'music_info': {},
                            'poster_delay': 0,
                            'cloud_edit_video_height': 1080,
                            'cloud_edit_video_width': 1920,
                            'cloud_edit_is_use_video_canvas': False,
                        },
                    },
                ],
            }

            response = self.session.post(
                'https://www.tiktok.com/tiktok/web/project/post/v1/',
                params=post_params,
                json=post_data,
            )
            
            published_video_id = response.json()["single_post_resp_list"][0]["item_id"]
            video_url = f"https://www.tiktok.com/@{nickname}/video/{published_video_id}"
            logger.info("Video uploaded successfully", url=video_url, description=video_description)
            
            return video_url
            
        except Exception as e:
            logger.error("Video upload failed", error=str(e))
            return None


def main() -> None:
    uploader = TikTokUploader("/home/emrovsky/Desktop/tiktok-gen/accounts/free_r0bux_ipxbdn/cookie.json")
    result = uploader.upload_video("gta5_1.mp4", "shqtz got no balls :3")
    if result:
        print(f"Upload successful: {result}")
    else:
        print("Upload failed")


if __name__ == "__main__":
    main()

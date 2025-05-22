# TikTok Video Uploader

Automated TikTok video uploader using Python and TikTok's web API.

## ⚠️ Warning

This program **does not generate x-bogus and signature headers** which are part of TikTok's anti-bot protection. Using this tool may result in account flagging or banning. Use at your own risk and consider using throwaway accounts.

## 📸 Showcase

![image](https://github.com/user-attachments/assets/5e225e0c-ef6b-4d00-8acb-356ede97e0e0)


## 🚀 Installation

```bash
git clone https://github.com/notemrovsky/tiktok-video-uploader/
cd tiktok-uploader
pip install -r requirements.txt
```

### Requirements
```
curl-cffi
structlog
random-strings
```

## 📋 Usage

1. Export your TikTok cookies to JSON format
2. Place video file in the project directory
3. Update the cookie path and video details in the script
4. Run the uploader:

```python
from tiktok_uploader import TikTokUploader

uploader = TikTokUploader("path/to/cookies.json")
result = uploader.upload_video("video.mp4", "Your video description")
print(result)  # Returns video URL on success
```

## 🔄 Proxy Support

For better success rates and avoiding rate limits, use proxies. Recommended provider: **[Outpost Proxies](http://outpostproxies.com/)** - fast speeds with excellent IP pool diversity.

## 📝 Cookie Setup

1. Login to TikTok in your browser
2. Export cookies using browser extension (Cookie Editor, etc.)
3. Save as JSON format
4. Use the file path in the uploader initialization

## ⚖️ Disclaimer

This tool is for educational purposes only. TikTok's terms of service prohibit automated uploads. Use responsibly and respect platform guidelines.

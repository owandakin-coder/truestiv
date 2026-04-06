import argparse
import json
import os
from pathlib import Path

import requests


def _api_base_url() -> str:
    return os.getenv("TRUSTIVE_API_URL", "http://localhost:8000").rstrip("/")


def _auth_headers() -> dict:
    api_key = os.getenv("TRUSTIVE_API_KEY", "")
    token = os.getenv("TRUSTIVE_TOKEN", "")
    if token:
        return {"Authorization": f"Bearer {token}"}
    if api_key:
        return {"X-API-Key": api_key}
    return {}


def _print_response(response: requests.Response):
    try:
        payload = response.json()
    except Exception:
        payload = {"status_code": response.status_code, "text": response.text}
    print(json.dumps(payload, indent=2))


def run_text_analysis(args):
    payload = {
        "channel": args.channel,
        "sender": args.sender,
        "phone_number": args.phone_number,
        "subject": args.subject,
        "content": args.content,
    }
    response = requests.post(
        f"{_api_base_url()}/api/analysis/analyze",
        json=payload,
        headers=_auth_headers(),
        timeout=20,
    )
    _print_response(response)


def run_feed(args):
    response = requests.get(
        f"{_api_base_url()}/api/community/threats",
        headers=_auth_headers(),
        timeout=20,
    )
    _print_response(response)


def run_geo_map(args):
    response = requests.get(
        f"{_api_base_url()}/api/intelligence/geo-map",
        headers=_auth_headers(),
        timeout=20,
    )
    _print_response(response)


def run_media(args):
    path = Path(args.file)
    with path.open("rb") as handle:
        response = requests.post(
            f"{_api_base_url()}/api/media/analyze",
            headers=_auth_headers(),
            data={"media_type": args.media_type},
            files={"file": (path.name, handle)},
            timeout=60,
        )
    _print_response(response)


def main():
    parser = argparse.ArgumentParser(prog="trustive-cli", description="Trustive AI command-line scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze text content")
    analyze.add_argument("--channel", default="email")
    analyze.add_argument("--sender", default="")
    analyze.add_argument("--phone-number", default="")
    analyze.add_argument("--subject", default="")
    analyze.add_argument("content")
    analyze.set_defaults(func=run_text_analysis)

    feed = subparsers.add_parser("feed", help="Fetch community threat feed")
    feed.set_defaults(func=run_feed)

    geo = subparsers.add_parser("geo-map", help="Fetch geographic threat map markers")
    geo.set_defaults(func=run_geo_map)

    media = subparsers.add_parser("media", help="Analyze image, audio, or video")
    media.add_argument("media_type", choices=["image", "audio", "video"])
    media.add_argument("file")
    media.set_defaults(func=run_media)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

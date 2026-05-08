import os
import boto3
from pathlib import Path


def _secret(env_var: str) -> str:
    val = os.environ.get(env_var)
    if val:
        return val
    path = Path("/run/secrets") / env_var
    if path.exists():
        return path.read_text().strip()
    raise RuntimeError(
        f"Required secret not found: set env var {env_var!r} "
        f"or mount it at {path}"
    )


S3_ENDPOINT = os.environ.get("UPS3RT_S3_ENDPOINT", "https://s3.twcstorage.ru")
S3_REGION = os.environ.get("UPS3RT_S3_REGION", "ru-1")

s3 = boto3.client(
    service_name='s3',
    endpoint_url=S3_ENDPOINT,
    aws_access_key_id=_secret('S3_ACCESS_KEY'),
    aws_secret_access_key=_secret('S3_SECRET_KEY'),
    region_name=S3_REGION,
)

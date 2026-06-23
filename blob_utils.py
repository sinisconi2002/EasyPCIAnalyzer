import io
import boto3
import os

def download_blob_to_memory(bucket_name, blob_name):
    # R2 necesită endpoint, access_key și secret_key
    # Acestea vor fi citite din variabilele de mediu din Render
    s3_client = boto3.client(
        's3',
        endpoint_url=os.getenv('R2_ENDPOINT'),
        aws_access_key_id=os.getenv('R2_ACCESS_KEY'),
        aws_secret_access_key=os.getenv('R2_SECRET_KEY')
    )
    
    response = s3_client.get_object(Bucket=bucket_name, Key=blob_name)
    binary_content = response['Body'].read()
    return io.BytesIO(binary_content)
import io
import boto3
import os

def download_blob_to_memory(bucket_name, blob_name):
    s3_client = boto3.client(
        's3',
        endpoint_url=os.getenv('R2_ENDPOINT'),
        aws_access_key_id=os.getenv('R2_ACCESS_KEY'),
        aws_secret_access_key=os.getenv('R2_SECRET_KEY'),
        region_name='auto'
    )
    
    response = s3_client.get_object(Bucket=bucket_name, Key=blob_name)
    binary_content = response['Body'].read()
    return io.BytesIO(binary_content)

def test_connection():
    try:
        # Aici printăm variabilele să vedem dacă le vede Python
        print(f"DEBUG: Endpoint: {os.getenv('R2_ENDPOINT')}")
        print(f"DEBUG: Key: {os.getenv('R2_ACCESS_KEY')[:5]}...")  # printăm doar începutul

        s3_client = boto3.client(
            's3',
            endpoint_url=os.getenv('R2_ENDPOINT'),
            aws_access_key_id=os.getenv('R2_ACCESS_KEY'),
            aws_secret_access_key=os.getenv('R2_SECRET_KEY'),
            region_name='auto'
        )

        # Test 1: Listăm bucket-urile să vedem dacă are voie
        response = s3_client.list_buckets()
        print("DEBUG: Succes! Am listat bucket-urile:", [b['Name'] for b in response['Buckets']])

        # Test 2: Încercăm să accesăm fișierul (HeadObject)
        s3_client.head_object(Bucket=os.getenv('R2_BUCKET_NAME'), Key='core_test_comisie')
        print("DEBUG: Succes! Fișierul a fost găsit.")

    except Exception as e:
        print(f"DEBUG EROARE: {str(e)}")

# Apelează asta în app.py la pornire
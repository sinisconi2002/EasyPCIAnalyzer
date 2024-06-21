import io
from azure.storage.blob import BlobServiceClient

def download_blob_to_memory(account_name, account_key, container_name, blob_name):
    connect_str = f"DefaultEndpointsProtocol=https;AccountName={account_name};AccountKey={account_key};EndpointSuffix=core.windows.net"
    blob_service_client = BlobServiceClient.from_connection_string(connect_str)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    
    binary_content = blob_client.download_blob().readall()
    return io.BytesIO(binary_content)

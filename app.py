from flask import Flask, request
from azure.storage.blob import BlobClient
import configparser
import os

app = Flask(__name__)

@app.route('/')
def starting_point():
    return "Dude, that's just the starting\n"
@app.route('/analyzer')
def analyze_core_dump():
    core_dump = request.args.get("core_dump")
    to_search = request.args.get("to_search")

    config = configparser.ConfigParser()
    config.read('config.ini')
    connection_string = config['General']['storage']
    container_name = config['General']['container']

    blob = BlobClient.from_connection_string(conn_str=connection_string, container_name=container_name, blob_name='core.2137')
    with open("coredump", "wb") as my_blob:
        blob_data = blob.download_blob()
        blob_data.readinto(my_blob)

    return "Ce faci momi? Fac laba".format(to_search)

if __name__ == '__main__':
    app.run()

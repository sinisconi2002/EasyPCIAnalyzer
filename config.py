import configparser

def load_rules(config_path='config.ini'):
    config = configparser.ConfigParser()
    config.read(config_path)
    rules = {key: config['Patterns'][key] for key in config['Patterns']}
    account_name = config['azure']['account_name']
    account_key = config['azure']['account_key']
    container_name = config['azure']['container_name']
    return rules, account_name, account_key, container_name

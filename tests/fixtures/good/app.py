import ast
import yaml

def parse(text):
    return ast.literal_eval(text), yaml.safe_load(text), yaml.load(text, Loader=yaml.SafeLoader)

from . import *

def color_print(*args, color=Colors.ENDC, **kwargs):
    # Call the original print function with the color
    message = ' '.join(map(str, args))
    builtins.print(f"{color}{message}{Colors.ENDC}", **kwargs)

def print_json_data(*args, data, keys=False, **kwargs):
    """
    Prints a dictionary with custom formatting without colons, indentation, or newlines
    """
    if (keys):
        return builtins.print(json.dumps(data, indent=2))
    
    for key, value in data.items():
        if isinstance(value, dict):
            # Print key followed by a space for nested dictionaries
            builtins.print(f"{key + ': ' if keys else ''}{", ".join(f'{k + ': ' if keys else ''} {v}' for k, v in value.items())}", end='\t')
        else:
            # Print key-value pair in a single line
            builtins.print(f"{key + ': ' if keys else ''}{value}", end='\t')
    builtins.print()  # End the line after printing all key-value pairs

def print(*args, **kwargs):
    """
    @brief Print message (with special options)
    @param args: message
    @param kwargs: color
    """
    global argv

    if (len(args) <= 0):
        return color_print(*args, color=Colors.ENDC, **kwargs)
    
    largs = list(map(str, args))[0].split(' ')
    if (len(largs) <= 0):
        return color_print(*args, color=Colors.ENDC, **kwargs)

    prefix = largs[0]
    if (argv.quiet and prefix in M_TYPES):
        return
    
    if (prefix == M_IMPORTANT):
        return color_print(*args, color=Colors.HEADER, **kwargs)
    elif (prefix == M_INFO):
        return color_print(*args, color=Colors.CYAN, **kwargs)
    elif (prefix == M_ERROR):
        return color_print(*args, color=Colors.FAIL, **kwargs)
    elif (prefix == M_SUCCESS):
        return color_print(*args, color=Colors.OKGREEN, **kwargs)
    elif (prefix in M_JSONS):
        largs.pop(0)
        if (argv.json or prefix == M_JSON_ENFORCED):
            return color_print(*largs, color=Colors.ENDC, **kwargs)
        
        largs = ' '.join(largs).replace("'", '"')
        return print_json_data(*args, data=json.loads(largs), keys=(prefix == M_JSON_KEYS), **kwargs)
    
    color_print(*args, color=Colors.ENDC, **kwargs)

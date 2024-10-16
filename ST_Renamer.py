# -*- coding: utf-8 -*-
# Ghidra Script: Automatically rename functions based on Debug_Info calls

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import re
import ast

def sanitize_name(name):
    # Remove leading and trailing underscores
    name = name.strip('_')
    # Split the name into numbers, considering one or more underscores
    numbers = re.split('_+', name)
    # Try to convert numbers to characters
    try:
        chars = [chr(int(num)) for num in numbers if num.isdigit()]
        if chars:
            name = ''.join(chars)
    except ValueError:
        pass  # If conversion fails, leave the name unchanged
    # Truncate at first comma, space, or opening parenthesis
    name = re.split(r'[,\s(]', name)[0]
    # Then sanitize the name, allowing colons
    sanitized = re.sub(r'[^a-zA-Z0-9_:]', '_', name)
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized
    return sanitized



def get_debug_info_function():
    funcs = getGlobalFunctions("Debug_Info")
    if funcs:
        print("Found 'Debug_Info' function at address {}".format(funcs[0].getEntryPoint()))
        return funcs[0]
    else:
        print("Function 'Debug_Info' not found")
        return None

def read_string(address):
    max_length = 1024  # Increased max length
    data = []
    mem = currentProgram.getMemory()
    for i in range(max_length):
        try:
            byte = mem.getByte(address.add(i))
            if byte == 0:
                break
            data.append(byte)
        except:
            print("Memory access error at address {}".format(address.add(i)))
            return None
    if data:
        try:
            return bytes(data).decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            print("Unicode decode error at address {}".format(address))
            return None
    return None

def process_function(func, decomp_interface, debug_info_addr, stats):
    timeout_secs = 20  # Increased decompilation timeout
    try:
        decomp_result = decomp_interface.decompileFunction(func, timeout_secs, monitor)
        if not decomp_result.decompileCompleted():
            print("Failed to decompile function {}: {}".format(
                func.getName(), decomp_result.getErrorMessage()))
            stats['failed'] += 1
            return
        high_func = decomp_result.getHighFunction()
        if high_func is None:
            print("No HighFunction for {}".format(func.getName()))
            stats['failed'] += 1
            return

        # Get the decompiled code as text
        decompiled_code = decomp_result.getDecompiledFunction().getC()

        # Search for calls to Debug_Info
        pattern = re.compile(r'\bDebug_Info\s*\((.*?)\);', re.DOTALL)
        matches = pattern.findall(decompiled_code)
        if matches:
            for args_str in matches:
                args = args_str.split(',')
                if len(args) >= 6:
                    sixth_arg = args[5].strip()
                    # Debug: Display the sixth argument
                    print("Sixth argument in function {}: {}".format(func.getName(), sixth_arg))
                    # Try to find the address in the sixth argument
                    address = None
                    # First, try to find an address directly in the argument
                    address_match = re.search(r'0x[0-9A-Fa-f]+', sixth_arg)
                    if address_match:
                        address_str = address_match.group(0)
                        address = toAddr(int(address_str, 16))
                    else:
                        # If no address found, try to extract address from symbol name
                        symbol_name_match = re.match(r'(s_\w+)', sixth_arg)
                        if symbol_name_match:
                            symbol_name = symbol_name_match.group(1)
                            # Try to extract address from symbol name
                            addr_in_name_match = re.search(r'_(0x[0-9A-Fa-f]+)$', symbol_name)
                            if addr_in_name_match:
                                addr_str = addr_in_name_match.group(1)
                                address = toAddr(int(addr_str, 16))
                            else:
                                # Try to extract address as hex digits at the end of the name
                                addr_in_name_match = re.search(r'_([0-9A-Fa-f]+)$', symbol_name)
                                if addr_in_name_match:
                                    addr_str = '0x' + addr_in_name_match.group(1)
                                    address = toAddr(int(addr_str, 16))
                    if address is not None:
                        print("Address extracted from sixth argument: {}".format(address))
                        func_name = read_string(address)
                        if func_name:
                            print("String read from memory: '{}'".format(func_name))
                            # Check if the string is a list representation
                            if func_name.startswith('[') and func_name.endswith(']'):
                                try:
                                    numbers = ast.literal_eval(func_name)
                                    if isinstance(numbers, list):
                                        chars = [chr(num) for num in numbers if isinstance(num, int)]
                                        func_name = ''.join(chars)
                                        print("Function name after parsing list: '{}'".format(func_name))
                                except Exception as e:
                                    print("Error parsing list of numbers: {}".format(e))
                            sanitized_name = sanitize_name(func_name)
                            try:
                                func.setName(sanitized_name, SourceType.USER_DEFINED)
                                stats['renamed'] += 1
                                print("Function {} renamed to {}".format(
                                    func.getEntryPoint(), sanitized_name))
                            except Exception as e:
                                print("Error renaming function: {} in function {}".format(e, func.getName()))
                                stats['failed'] += 1
                        else:
                            print("Failed to read function name at address {}".format(address))
                            stats['failed'] += 1
                    else:
                        print("No address found in sixth argument of function {}: {}".format(func.getName(), sixth_arg))
                        stats['failed'] += 1
                else:
                    print("Debug_Info call in function {} does not have enough arguments".format(func.getName()))
                    stats['failed'] += 1
                break  # Assuming we are interested in only one call
        else:
            print("No call to Debug_Info found in function {}".format(func.getName()))
            stats['failed'] += 1
        stats['processed'] += 1
    except Exception as e:
        print("Error processing function {}: {}".format(func.getName(), str(e)))
        stats['failed'] += 1

def main():
    try:
        print("Starting script...")
        debug_info_func = get_debug_info_function()
        if not debug_info_func:
            return
        debug_info_addr = debug_info_func.getEntryPoint()

        decomp_interface = DecompInterface()
        decomp_interface.openProgram(currentProgram)
        global monitor
        monitor = ConsoleTaskMonitor()

        reference_manager = currentProgram.getReferenceManager()
        references = reference_manager.getReferencesTo(debug_info_addr)
        print("Fetching references to 'Debug_Info'...")
        functions_to_process = set()
        count = 0
        max_references = 5000  # Adjust as needed
        for ref in references:
            try:
                count += 1
                if count > max_references:
                    print("Reference limit reached: {}".format(max_references))
                    break
                ref_type = ref.getReferenceType()
                if ref_type.isCall():
                    from_addr = ref.getFromAddress()
                    func = getFunctionContaining(from_addr)
                    if func is not None and not func.isThunk():
                        functions_to_process.add(func)
            except Exception as e:
                print("Error processing reference {}: {}".format(count, str(e)))
                continue
        total_functions = len(functions_to_process)
        print("Number of functions to process: {}".format(total_functions))

        stats = {'processed': 0, 'renamed': 0, 'failed': 0}
        for idx, func in enumerate(functions_to_process, 1):
            progress_percent = (idx / total_functions) * 100
            print("Processing function {} of {} ({:.2f}%)".format(idx, total_functions, progress_percent))
            process_function(func, decomp_interface, debug_info_addr, stats)
            print("Processed: {}, Renamed: {}, Failures: {}".format(
                stats['processed'], stats['renamed'], stats['failed']))

        print("Processing completed.")
        print("Total functions processed: {}".format(stats['processed']))
        print("Total functions renamed: {}".format(stats['renamed']))
        print("Total failures: {}".format(stats['failed']))
    except Exception as e:
        print("An error occurred: {}".format(str(e)))

if __name__ == "__main__":
    main()

import argparse
import concurrent.futures
import os
import yara
import time
import sys
import hashlib
# import pyautogui
import signal



def read_md5_hashes_file(file_path):
    """Read MD5 hashes from the given file."""
    md5_hashes = []
    with open(file_path, 'r') as f:
        for line in f:
            md5_hashes.append(line.strip())
    return md5_hashes

def get_file_md5(file_path):
    """Calculate the MD5 hash of a file."""
    md5_hash = hashlib.md5()
    with open(file_path, 'rb') as f:
        # Read the file in chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b''):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def compare_hashes_with_file(directory_path, file_hashes):
    """Compare MD5 hashes of files in the directory with the hashes in the file."""
    
    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            md5_hash = get_file_md5(file_path)
            if md5_hash in file_hashes:
                print(f"File '{filename}' is a malware detected by hash.")
  
            
  
        

class YaraScanner:
    def __init__(self, rule_file, num_threads):
        self.rule_file = rule_file
        self.num_threads = num_threads
        self.compiled_rules = None

    def compile_rules(self):
        self.compiled_rules = yara.compile(filepath=self.rule_file)

    def scan_file(self, file_path):
        try:
            # Read the full file content
            with open(file_path, "rb") as file:
                file_content = file.read()

            # Perform the scan
            matches = self.compiled_rules.match(data=file_content)

            if matches:
                output_lines = []
                output_lines.append(f"\nYARA rules matched the file: {file_path}\n")
                for rule_name, rule_match_list in matches.items():
                    for rule_match in rule_match_list:
                        output_lines.append(f"Matched Rule: {rule_match['rule']}")
                        for string_match in rule_match["strings"]:
                            output_lines.append("  - String: " + string_match["data"])
                            output_lines.append("    Offset: " + str(string_match["offset"]))
                            output_lines.append("    Identifier: " + string_match["identifier"])
                            output_lines.append("    Flags: " + str(string_match["flags"]))
                            output_lines.append("_" * 40)
                return output_lines

        except FileNotFoundError:
            print(f"File '{file_path}' does not exist.")
            time.sleep()
            
            sys.exit()
        except PermissionError:
            print(f"permission error. skipping {file_path}..... ")
            time.sleep(1)
            return None

    def scan_directory(self, directory, recursive=False):
        
    
            if os.path.exists(directory):
                
                files = []
                
                if recursive:
                    for root, _, filenames in os.walk(directory):
                        for filename in filenames:
                            file_extension = os.path.splitext(filename)[-1]
                            if file_extension.lower()==".yar":
                                continue
                            elif filename.startswith("YARA"):
                                continue
                            
                            else:
                                try:
                                    
                                    file_path = os.path.join(root, filename)
                                    file_size = os.path.getsize(file_path)
                                except FileNotFoundError:
                                    print (f"skipping the temporary files: {file_path}")
                                    time.sleep(1)
                            
                                
                                if file_size > 5*1024*1024*1042:
                                    print("The file is greater than 5 GB skipping.........")
                                    time.sleep(1)
                                    continue
                                
                                # file_path = os.path.join(root, filename)
                                else:
                                    print("scanning "+file_path)
                                    files.append(file_path)
                else:
                    for filename in os.listdir(directory):
                        file_extension = os.path.splitext(filename)[-1]
                        if file_extension.lower()==".yar":
                            continue
                        elif filename.startswith("YARA"):
                            continue
                        # elif file_size>5*1024*1024*1024:
                        #     continue
                        else:
                            file_path = os.path.join(directory, filename)
                            print("scanning "+file_path)
                            if os.path.isfile(file_path):
                                files.append(file_path)
            
                    

                # Submit the scanning tasks
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                    scan_tasks = [executor.submit(self.scan_file, file_path) for file_path in files]

                    # Wait for all scanning tasks to finish
                    output_lines = []
                    for file_path, scan_task in zip(files, concurrent.futures.as_completed(scan_tasks)):
                        result = scan_task.result()
                        if result:
                            output_lines.extend(result)

                if not output_lines:
                    logo =  """\n\n\n
                                
                                                                                                                
                                                                                                                
/$$   /$$  /$$$$$$   /$$$$$$  /$$$$$$         /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$ 
| $$  | $$ |____  $$ /$$__  $$|____  $$       /$$_____/ /$$_____/ |____  $$| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$
| $$  | $$  /$$$$$$$| $$  \__/ /$$$$$$$      |  $$$$$$ | $$        /$$$$$$$| $$  \ $$| $$  \ $$| $$$$$$$$| $$  \__/
| $$  | $$ /$$__  $$| $$      /$$__  $$       \____  $$| $$       /$$__  $$| $$  | $$| $$  | $$| $$_____/| $$      
|  $$$$$$$|  $$$$$$$| $$     |  $$$$$$$       /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$| $$  | $$|  $$$$$$$| $$      
\____  $$ \_______/|__/      \_______/      |_______/  \_______/ \_______/|__/  |__/|__/  |__/ \_______/|__/      
/$$  | $$                                                                                                         
|  $$$$$$/                                                                                                         
\______/                                                                                                          

                                                                                                                                                                                                        

                                \n\n"""
                    output_lines.append(f"{logo}")
                    output_lines.append(f"YARA rules did not match any file in the directory '{directory}'.")
                return output_lines
            else:
                print(f"The {directory} doesn't exists")
                sys.exit()
        
                # return
    
            
            

    def start_scan(self, file_path, directory, recursive=False):
        
        if file_path:
            if not self.compiled_rules:
                self.compile_rules()
            output_lines = self.scan_file(file_path)
            if output_lines:
                return "\n".join(output_lines)
        elif directory:
            if not self.compiled_rules:
                self.compile_rules()
            output_lines = self.scan_directory(directory, recursive=recursive)
            if output_lines:
                return "\n".join(output_lines)

        return None

    # def signal_handler(signal, frame):
    #     print("\nScan interrupted by user.")
    #     sys.exit(0)
def main():
    parser = argparse.ArgumentParser(description="YARA Scanner")
    parser.add_argument("-f", "--file", help="File path to scan")
    parser.add_argument("-d", "--directory", help="Directory path to scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive scanning")
    parser.add_argument("-H","--hash",action="store_true",help="scan wish hash")
    parser.add_argument("-t", "--threads", type=int, default=2, help="Number of threads (default: 2)")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()
    dir=args.directory
    if args.hash:
        hashes_file_path = "C:\\Users\\Acer\\OneDrive - Softwarica College\\Desktop\\course work python\\coursework2\\hash.txt"
        file_hashes = read_md5_hashes_file(hashes_file_path)

    
        compare_hashes_with_file(dir, file_hashes) 

      
             


    
    if args.file or args.directory:
        rule_file_path = "C:\\Users\\Acer\\OneDrive - Softwarica College\\Desktop\\course work python\\test_rule.yar"
        num_threads = args.threads
            # Read MD5 hashes from the file


        scanner = YaraScanner(rule_file_path, num_threads)
        output = scanner.start_scan(args.file, args.directory, recursive=args.recursive)

        if output:
            if args.output:
                if args.output.startswith("YARA_") and args.output.endswith(".txt"):
                    with open(args.output, "a") as output_file:
                        output_file.write(output)
                    print(f"File saved to {args.output}")
                elif args.output.startswith("YARA_") and not args.output.endswith(".txt"):
                    with open(args.output + ".txt", "a") as output_file:
                        output_file.write(output)
                    print(f"File saved to {args.output + '.txt'}")
                elif not args.output.startswith("YARA_") and args.output.endswith(".txt"):
                    with open("YARA_" + args.output, "a") as output_file:
                        output_file.write(output)
                    print(f"File saved to YARA_{args.output}")
                elif not args.output.startswith("YARA_") and not args.output.endswith(".txt"):
                    with open("YARA_" + args.output + ".txt", "a") as output_file:
                        output_file.write(output)
                    print(f"File saved to YARA_{args.output}.txt")
            else:
                print(output)
        elif output== "directory_not_found":
            print(output)
        else:
            print("none")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
    

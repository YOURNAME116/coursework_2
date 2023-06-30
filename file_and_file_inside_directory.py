import argparse
import concurrent.futures
import os
import yara


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
            return None

    def scan_directory(self, directory):
        # List all files in the directory
        files = []
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if os.path.isfile(file_path):
                file_extension = os.path.splitext(filename)[-1]
                if file_extension.lower() == ".yar":
                    continue
                elif filename.startswith("YARA"):
                    continue
                else:
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
            output_lines.append(f"YARA rules did not match any file in the directory '{directory}'")
        return output_lines

    def start_scan(self, file_path, directory):
        if file_path:
            if not self.compiled_rules:
                self.compile_rules()
            output_lines = self.scan_file(file_path)
            if output_lines:
                return "\n".join(output_lines)
        elif directory:
            if not self.compiled_rules:
                self.compile_rules()
            output_lines = self.scan_directory(directory)
            if output_lines:
                return "\n".join(output_lines)

        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="YARA Scanner")
    parser.add_argument("-f", "--file", help="File path to scan")
    parser.add_argument("-d", "--directory", help="Directory path to scan")
    parser.add_argument("-t", "--threads", type=int, default=2, help="Number of threads (default: 2)")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    if args.file or args.directory:
        rule_file_path = "test_rule.yar"
        num_threads = args.threads

        scanner = YaraScanner(rule_file_path, num_threads)
        output = scanner.start_scan(args.file, args.directory)
        
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
        else:
            print("No matches found.")
    else:
        parser.print_help()

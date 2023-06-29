import argparse
import concurrent.futures
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
                print("YARA rules matched the file!")
                for rule_name, rule_match_list in matches.items():
                    for rule_match in rule_match_list:
                        print(f"Matched Rule: {rule_match['rule']}")
                        for string_match in rule_match["strings"]:
                            print("  - String:", string_match["data"])
                            print("    Offset:", string_match["offset"])
                            print("    Identifier:", string_match['identifier'])
                            print("    Flags:", string_match['flags'])
                            print("_"*40+"\n")
            else:
                print("YARA rules did not match the file.")

        except FileNotFoundError:
            print("File does not exist.")

    def start_scan(self, file_path):
        # Create a ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Submit the compilation task
            compile_task = executor.submit(self.compile_rules)

            # Wait for the compilation task to finish
            compile_task.result()

            # Submit the scanning task
            scan_task = executor.submit(self.scan_file, file_path)

            # Wait for the scanning task to finish
            scan_task.result()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="YARA Scanner")
    parser.add_argument("-f", "--file", help="File path to scan")
    parser.add_argument("-t", "--threads", type=int, default=2, help="Number of threads (default: 2)")
    args = parser.parse_args()

    if args.file:
        rule_file_path = "test_rule.yar"
        num_threads = args.threads

        scanner = YaraScanner(rule_file_path, num_threads)
        scanner.start_scan(args.file)
    else:
        parser.print_help()

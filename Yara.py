import yara
import os
class YaraScanner:
    def __init__(self, rule_directory):
        rule_files = [os.path.join(rule_directory, rule) for rule in os.listdir(rule_directory)]
        self.rules = yara.compile(filepaths={os.path.splitext(os.path.basename(rule))[0]: rule for rule in rule_files})

    def scan_file(self, file_path):
        # Scan the file with all compiled rules
        try:
            matches = self.rules.match(file_path)

            # Check if there are matches
            if matches:
                #print(f"The file {file_path} matches the following YARA rules:")
                rules = []
                for match in matches:
                    rules.append(match)
                Report = f"The file {file_path} matches the following YARA rules:" +f"{rules}"
                print(Report)
                return 1 , Report
        except:
            #print(f"The file {file_path} does not match any YARA rules in the directory.")
            return 0 , "Non-Malware"



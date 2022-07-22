import json
import os
import re

from .utils import print_bold

SCAN_TYPE_PIP = 'PYPI'
SCAN_TYPE_NPM = 'NPM'

class Validator():
    vulnerable_files = None
    path = None
    files_to_validate = None

    def __init__(self, path: str):
        self.vulnerable_files = {}
        self.files_to_validate = []
        self.path = path

    def discover(self):
        """Checks the Scanner's assigned path for any package management files which need to be scanned
        for potential vulnerabilities.
        """
        print_bold('Scanning...')

        for file in os.listdir(self.path):
            if 'requirements.txt' in file:
                self.files_to_validate.append({'name': file, 'scan_type': SCAN_TYPE_PIP})
            if 'package.json' in file:
                self.files_to_validate.append({'name': file, 'scan_type': SCAN_TYPE_NPM})


    def validate(self):
        """Validates that all discovered package management files contain exact version pinning.
        """
        if not self.files_to_validate:
            print('No files to validate, skipping validation.')
            exit()
        for file in self.files_to_validate:
            full_path = self._build_full_path(file['name'])

            if file['scan_type'] == SCAN_TYPE_PIP:
                self._scan_pip(file, full_path)
            elif file['scan_type'] == SCAN_TYPE_NPM:
                self._scan_npm(file, full_path)

    def _build_full_path(self, path: str):
        return os.path.join(self.path, path)

    def _scan_pip(self, file: str, full_path: str):
        with open(full_path) as f:
            for i, l in enumerate(f.readlines()):
                parts = l.split('==')
                if len(parts) != 2:
                    issue = {
                        'file': file['name'],
                        'dependency': parts[0].strip(),
                    }
                    if full_path not in self.vulnerable_files:
                        self.vulnerable_files[full_path] = {
                            'scan_type': SCAN_TYPE_PIP,
                            'issues': [issue]
                        }
                    else:
                        self.vulnerable_files[full_path]['issues'].append(issue)

    def _scan_npm(self, file: str, full_path: str):
        pattern = re.compile("^\d+.\d+.\d+$")
        with open(full_path) as f:
            package_json = json.load(f)
            dependency_dicts_to_scan = []
            if 'dependencies' in package_json:
                dependency_dicts_to_scan.append(package_json['dependencies'])
            if 'devDependencies' in package_json:
                dependency_dicts_to_scan.append(package_json['devDependencies'])

            for dependencies in dependency_dicts_to_scan:
                for dependency, _ in dependencies.items():
                    if not pattern.match(dependency):
                        issue = {
                            'file': file['name'],
                            'dependency': dependency.strip()
                        }
                        if full_path not in self.vulnerable_files:
                            self.vulnerable_files[full_path] = {
                                'scan_type': SCAN_TYPE_NPM,
                                'issues': [issue]
                            }
                        else:
                            self.vulnerable_files[full_path]['issues'].append(issue)

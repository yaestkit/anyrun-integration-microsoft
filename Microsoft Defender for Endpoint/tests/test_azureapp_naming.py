"""Offline name-expression checks; Azure's uniqueString output is a fixed fixture.

Run after test_resource_naming.ps1 -ExportFixtures <file> with
MDE_NAMING_FIXTURES=<file> python3 -m unittest discover -s <tests> -p test_azureapp_naming.py
This does not evaluate Azure's hashing algorithm or deploy resources.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'AzureApp' / '1.1.4'
HASH = 'abcdefghi2345'


class NameExpressions:
    """Evaluate only the string functions used by the naming variables."""
    def __init__(self, template, instance, existing_function=''):
        self.variables = template['variables']
        self.parameters = {'instanceName': instance, 'existingFunctionAppName': existing_function}

    def variable(self, name):
        return self.evaluate(self.variables[name])

    def evaluate(self, expression):
        expression = expression[1:-1].replace('resourceGroup().id', "'rg-test'")
        tokens = re.findall(r"'[^']*'|[A-Za-z][A-Za-z0-9]*|[0-9]+|[(),]", expression)
        offset = 0

        def parse():
            nonlocal offset
            token = tokens[offset]
            offset += 1
            if token.startswith("'"):
                return token[1:-1]
            if token.isdigit():
                return int(token)
            if tokens[offset] != '(':
                raise AssertionError('Unsupported naming expression: ' + expression)
            offset += 1
            args = []
            if tokens[offset] != ')':
                args.append(parse())
                while tokens[offset] == ',':
                    offset += 1
                    args.append(parse())
            if tokens[offset] != ')':
                raise AssertionError('Invalid expression: ' + expression)
            offset += 1
            functions = {
                'parameters': lambda name: self.parameters[name],
                'variables': self.variable,
                'if': lambda condition, yes, no: yes if condition else no,
                'not': lambda condition: not condition,
                'empty': lambda value: value == '',
                'concat': lambda *values: ''.join(values),
                'take': lambda value, length: value[:length],
                'uniqueString': lambda *values: HASH,
            }
            return functions[token](*args)

        value = parse()
        if offset != len(tokens):
            raise AssertionError('Trailing expression tokens: ' + expression)
        return value


class AzureAppNamingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_path = os.environ.get('MDE_NAMING_FIXTURES')
        if fixture_path:
            cls.fixtures = json.loads(Path(fixture_path).read_text())
            return
        pwsh = shutil.which('pwsh')
        if not pwsh:
            raise unittest.SkipTest('PowerShell 7 or MDE_NAMING_FIXTURES is required for ARM/installer comparison')
        with tempfile.TemporaryDirectory() as directory:
            fixture_path = Path(directory) / 'naming.json'
            subprocess.run([pwsh, '-NoProfile', '-File', str(Path(__file__).with_name('test_resource_naming.ps1')),
                            '-ExportFixtures', str(fixture_path)], check=True, capture_output=True, text=True)
            cls.fixtures = json.loads(fixture_path.read_text())

    def template(self, kind):
        folder = 'Sandbox' if kind == 'Sandbox' else 'TI-Feeds'
        return json.loads((APP / folder / 'mainTemplate.json').read_text())

    def test_arm_names_match_executed_powershell_for_short_and_maximum_instances(self):
        for case in self.fixtures['Cases']:
            kind = case['Connector']
            with self.subTest(kind=kind, instance=case['Instance']):
                t = self.template(kind)
                e = NameExpressions(t, case['Instance'])
                n = case['Names']
                for variable, param in [('functionAppName', kind+'FunctionName'),
                                        ('logicAppName', kind+'LogicAppName'),
                                        ('storageAccountName', kind+'StorageAccountName'),
                                        ('newWorkspaceName', 'LogAnalyticsWorkspaceName')]:
                    self.assertEqual(e.variable(variable), n[param])
                self.assertEqual(e.variable('hostingPlanName'), f'ANYRUN-{kind}-MDE-{case["Instance"]}-Plan')
                self.assertEqual(e.variable('appInsightsName'), f'ANYRUN-{kind}-MDE-{case["Instance"]}-AI')
                self.assertLessEqual(len(e.variable('functionAppName')), 60)
                self.assertRegex(e.variable('storageAccountName'), r'^[a-z0-9]{3,24}$')
                self.assertIn(self.fixtures['HashExpression'][1:-1], t['variables']['nameHash'])

    def test_empty_instance_keeps_legacy_azureapp_names(self):
        for kind in ('Sandbox', 'Feeds'):
            with self.subTest(kind=kind):
                e = NameExpressions(self.template(kind), '')
                fn = f'anyrun-{kind.lower()}-mde-{HASH}'
                self.assertEqual(e.variable('functionAppName'), fn)
                self.assertEqual(e.variable('logicAppName'), f'ANYRUN-{kind}-MDE-LA')
                self.assertEqual(e.variable('hostingPlanName'), fn)
                self.assertEqual(e.variable('appInsightsName'), fn)
                self.assertEqual(e.variable('newWorkspaceName'), fn+'-law')

    def test_existing_function_override_was_removed(self):
        # Azure App 1.1.4 removed the 1.1.2 test-instance override field.
        for kind in ('Sandbox', 'Feeds'):
            t = self.template(kind)
            self.assertNotIn('existingFunctionAppName', t['parameters'])
            self.assertIn("resourceId('Microsoft.Web/sites', variables('functionAppName'))", json.dumps(t))

    def test_ui_outputs_and_case_sensitive_name_constraints(self):
        for folder, kind in [('Sandbox','Sandbox'), ('TI-Feeds','Feeds')]:
            t = self.template(kind)
            ui = json.loads((APP/folder/'createUiDefinition.json').read_text())['parameters']
            fields = {x['name']: x for x in ui['basics']}
            instance = fields['instanceName']
            self.assertEqual(instance['defaultValue'], "[toLower(take(replace(guid(), '-', ''), 6))]")
            self.assertNotIn('existingFunctionAppName', ui['outputs'])
            self.assertNotIn('existingFunctionAppName', fields)
            self.assertIsNone(re.fullmatch(instance['constraints']['regex'], 'ABC'))
            self.assertIsNotNone(re.fullmatch(instance['constraints']['regex'], 'demo01'))
            self.assertIn(f'ANYRUN-{kind}-MDE-<instance>-LA', fields['instanceInfo']['options']['text'])

    def test_nested_deployment_packages_match_the_edited_templates(self):
        for folder, stem in [('Sandbox','sandbox'), ('TI-Feeds','ti-feeds')]:
            with zipfile.ZipFile(APP/f'anyrun-{stem}-mde-1.1.4.zip') as archive:
                self.assertIsNone(archive.testzip())
                for name in ('mainTemplate.json','createUiDefinition.json'):
                    self.assertEqual(archive.read(name), (APP/folder/name).read_bytes())
                runtime=f'artifacts/ANYRUN-{ "Sandbox" if folder=="Sandbox" else "Feeds" }-MDE-FA.zip'
                self.assertEqual(archive.read(runtime), (APP/folder/runtime).read_bytes())


if __name__ == '__main__':
    unittest.main()

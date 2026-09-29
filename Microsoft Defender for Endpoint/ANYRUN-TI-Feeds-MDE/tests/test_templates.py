import json
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
PACKAGE_PATH = ROOT / 'Function App' / 'ANYRUN-Feeds-MDE-FA.zip'
SOURCE_DIR = ROOT / 'src'


class LogicAppTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template_path = ROOT / 'Logic App' / 'ANYRUN-Feeds-MDE-LA.json'
        cls.template = json.loads(template_path.read_text())

    def test_minimum_confidence_threshold_is_configured_in_initialize_variables(self):
        deployment_parameter = self.template['parameters']['minimum_confidence_threshold']
        self.assertEqual(deployment_parameter['defaultValue'], 50)
        self.assertEqual(deployment_parameter['minValue'], 1)
        self.assertEqual(deployment_parameter['maxValue'], 100)

        workflow_resource = self.template['resources'][0]['properties']
        self.assertNotIn(
            'Minimum Confidence',
            workflow_resource['definition']['parameters'],
        )
        self.assertNotIn(
            'Minimum Confidence',
            workflow_resource['parameters'],
        )

    def test_minimum_confidence_threshold_is_forwarded_to_function(self):
        workflow = self.template['resources'][0]['properties']['definition']
        variables = workflow['actions']['Initialize_variables']['inputs']['variables']
        variable = next(
            item for item in variables
            if item['name'] == 'minimum_confidence_threshold'
        )
        function_body = workflow['actions']['ANYRUNFeeds-AnyRunFeeds']['inputs']['body']

        self.assertEqual(
            variable['value'],
            "[parameters('minimum_confidence_threshold')]",
        )
        self.assertEqual(
            function_body['minimum_confidence_threshold'],
            "@variables('minimum_confidence_threshold')",
        )
        self.assertEqual(
            set(function_body),
            {'feed_fetch_depth', 'minimum_confidence_threshold'},
        )

    def test_runs_are_serial_and_function_retries_are_disabled(self):
        workflow = self.template['resources'][0]['properties']['definition']
        self.assertEqual(
            workflow['triggers']['Recurrence']['runtimeConfiguration']['concurrency']['runs'],
            1,
        )
        self.assertEqual(
            workflow['actions']['ANYRUNFeeds-AnyRunFeeds']['inputs']['retryPolicy'],
            {'type': 'none'},
        )


class FunctionAppTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template_path = ROOT / 'Function App' / 'ANYRUN-Feeds-MDE-FA.json'
        cls.template = json.loads(template_path.read_text())

    def test_role_assignment_has_principal_type_and_replaces_fixed_delay(self):
        resource_types = {resource['type'] for resource in self.template['resources']}
        self.assertNotIn('Microsoft.Resources/deploymentScripts', resource_types)
        deployment = next(
            resource for resource in self.template['resources']
            if resource.get('name') == 'AssignFunctionStorageRole'
        )
        role = deployment['properties']['template']['resources'][0]
        self.assertEqual(role['properties']['principalType'], 'ServicePrincipal')
        extension = next(
            resource for resource in self.template['resources']
            if resource['type'] == 'Microsoft.Web/sites/extensions'
        )
        self.assertEqual(
            extension['dependsOn'],
            ["[resourceId('Microsoft.Resources/deployments', 'AssignFunctionStorageRole')]"],
        )

    def test_repository_template_package_uri_is_not_pinned_to_a_commit(self):
        extension = next(
            resource for resource in self.template['resources']
            if resource['type'] == 'Microsoft.Web/sites/extensions'
        )
        package_uri = extension['properties']['packageUri']
        self.assertTrue(package_uri.startswith('https://raw.githubusercontent.com/'))
        self.assertIn('/anyrun/anyrun-integration-microsoft/', package_uri)
        self.assertIn('/refs/heads/main/', package_uri)
        self.assertNotRegex(package_uri, r'/[0-9a-f]{40}/')

    def test_deployment_zip_contains_the_reviewed_sources(self):
        packaged_files = (
            'host.json',
            'requirements.txt',
            'ANYRUN-Feeds-MDE-FA/function.json',
            'ANYRUN-Feeds-MDE-FA/config.py',
            'ANYRUN-Feeds-MDE-FA/anyrun_connector.py',
            'ANYRUN-Feeds-MDE-FA/anyrunfeeds.py',
            'ANYRUN-Feeds-MDE-FA/utils.py',
            'ANYRUN-Feeds-MDE-FA/__init__.py',
        )
        with zipfile.ZipFile(PACKAGE_PATH) as package:
            for relative_path in packaged_files:
                with self.subTest(relative_path=relative_path):
                    self.assertEqual(
                        package.read(relative_path),
                        (SOURCE_DIR / relative_path).read_bytes(),
                    )


if __name__ == '__main__':
    unittest.main()

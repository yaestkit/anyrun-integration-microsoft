import json
import unittest
import zipfile
from pathlib import Path


COMPONENT_DIR = Path(__file__).parents[1]
TEMPLATE_PATH = COMPONENT_DIR / 'Function App' / 'ANYRUN-Sandbox-MDE-FA.json'
PACKAGE_PATH = COMPONENT_DIR / 'Function App' / 'ANYRUN-Sandbox-MDE-FA.zip'
SOURCE_DIR = COMPONENT_DIR / 'src'


class ArmTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = json.loads(TEMPLATE_PATH.read_text())

    def test_role_assignment_name_is_derived_from_principal_in_nested_template(self):
        deployment = next(
            resource
            for resource in self.template['resources']
            if resource.get('name') == 'AssignFunctionStorageRole'
        )
        role_assignment = deployment['properties']['template']['resources'][0]

        self.assertEqual(deployment['type'], 'Microsoft.Resources/deployments')
        self.assertNotIn('reference(', deployment['name'])
        self.assertEqual(
            role_assignment['type'],
            'Microsoft.Authorization/roleAssignments',
        )
        self.assertIn("parameters('principalId')", role_assignment['name'])
        self.assertIn("parameters('storageAccountName')", role_assignment['name'])
        self.assertIn("parameters('storageRoleDefinitionId')", role_assignment['name'])
        self.assertEqual(
            role_assignment['properties']['principalType'],
            'ServicePrincipal',
        )

    def test_deployment_zip_contains_the_reviewed_sources(self):
        packaged_files = {
            'ANYRUN-Sandbox-MDE-FA/anyrun_connector.py',
            'ANYRUN-Sandbox-MDE-FA/function.json',
            'ANYRUN-Sandbox-MDE-Worker/worker.py',
            'ANYRUN-Sandbox-MDE-Worker/function.json',
            'ANYRUN-Sandbox-MDE-Status/status.py',
            'ANYRUN-Sandbox-MDE-Status/function.json',
            'anyrun_mde_core/config.py',
            'anyrun_mde_core/api_errors.py',
            'anyrun_mde_core/defender.py',
            'anyrun_mde_core/job_status.py',
            'anyrun_mde_core/processor.py',
            'anyrun_mde_core/sandbox_client.py',
            'host.json',
            'anyrun_mde_core/ANYRUN-SB-DEFENDER.ps1',
            'anyrun_mde_core/ANYRUN-SB-DEFENDER.sh',
        }

        with zipfile.ZipFile(PACKAGE_PATH) as package:
            for filename in packaged_files:
                with self.subTest(filename=filename):
                    self.assertEqual(
                        package.read(filename),
                        (SOURCE_DIR / filename).read_bytes(),
                    )

    def test_package_deployment_depends_on_role_assignment_not_fixed_delay(self):
        resource_types = {resource['type'] for resource in self.template['resources']}
        self.assertNotIn('Microsoft.Resources/deploymentScripts', resource_types)
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
        self.assertEqual(extension['properties']['packageUri'], "[parameters('packageUri')]")
        package_uri = self.template['parameters']['packageUri']['defaultValue']
        self.assertTrue(package_uri.startswith('https://raw.githubusercontent.com/'))
        self.assertIn('/yaestkit/anyrun-integration-microsoft/', package_uri)
        self.assertIn('/refs/heads/asyncv2/', package_uri)
        self.assertNotRegex(package_uri, r'/[0-9a-f]{40}/')

    def test_evidence_container_has_one_day_cleanup_policy(self):
        policy = next(
            resource for resource in self.template['resources']
            if resource['type'] == 'Microsoft.Storage/storageAccounts/managementPolicies'
        )
        self.assertEqual(policy['condition'], "[parameters('ConfigureEvidenceLifecyclePolicy')]")
        self.assertFalse(
            self.template['parameters']['ConfigureEvidenceLifecyclePolicy']['defaultValue']
        )
        lifecycle_description = self.template['parameters'][
            'ConfigureEvidenceLifecyclePolicy'
        ]['metadata']['description']
        self.assertIn('one day', lifecycle_description)
        self.assertIn('seven days', lifecycle_description)
        rule = policy['properties']['policy']['rules'][0]
        self.assertTrue(rule['enabled'])
        self.assertEqual(rule['type'], 'Lifecycle')
        self.assertEqual(
            rule['definition']['actions']['baseBlob']['delete']['daysAfterModificationGreaterThan'],
            1,
        )
        self.assertEqual(rule['definition']['filters']['blobTypes'], ['blockBlob'])
        self.assertIn("AzureBlobContainerName", rule['definition']['filters']['prefixMatch'][0])

        status_rule = policy['properties']['policy']['rules'][1]
        self.assertEqual(status_rule['name'], 'delete-anyrun-job-status-after-seven-days')
        self.assertEqual(
            status_rule['definition']['actions']['baseBlob']['delete'][
                'daysAfterModificationGreaterThan'
            ],
            7,
        )
        self.assertIn('jobStatusContainerName', status_rule['definition']['filters']['prefixMatch'][0])

    def test_private_job_status_container_and_app_setting_are_deployed(self):
        containers = [
            resource for resource in self.template['resources']
            if resource['type'] == 'Microsoft.Storage/storageAccounts/blobServices/containers'
        ]
        status_container = next(
            resource for resource in containers
            if "jobStatusContainerName" in resource['name']
        )
        self.assertEqual(status_container['properties']['publicAccess'], 'None')

        site = next(
            resource for resource in self.template['resources']
            if resource['type'] == 'Microsoft.Web/sites'
        )
        settings = {
            item['name']: item['value']
            for item in site['properties']['siteConfig']['appSettings']
        }
        self.assertEqual(
            settings['AnyRunJobStatusContainerName'],
            "[variables('jobStatusContainerName')]",
        )

    def test_endpoint_scripts_allow_partial_success_but_fail_if_nothing_uploaded(self):
        powershell = (SOURCE_DIR / 'anyrun_mde_core' / 'ANYRUN-SB-DEFENDER.ps1').read_text()
        shell = (SOURCE_DIR / 'anyrun_mde_core' / 'ANYRUN-SB-DEFENDER.sh').read_text()
        self.assertIn('$uploadedCount -eq 0', powershell)
        self.assertIn('$uploadedCount -lt $targets.Count', powershell)
        self.assertIn('uploadedCount == 0', shell)
        self.assertIn('uploadedCount < ${#filePaths[@]}', shell)
        self.assertIn('SecurityProtocolType]::Tls12', powershell)


if __name__ == '__main__':
    unittest.main()

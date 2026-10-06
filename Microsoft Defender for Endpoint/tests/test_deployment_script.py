import hashlib
import json
import re
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "Scripts" / "Deploy-ANYRUNMDEConnector.ps1"
DOC = ROOT / "AUTOMATED-DEPLOYMENT.md"
SANDBOX_FUNCTION = ROOT / "ANYRUN-Sandbox-MDE" / "Function App" / "ANYRUN-Sandbox-MDE-FA.json"
SANDBOX_LOGIC = ROOT / "ANYRUN-Sandbox-MDE" / "Logic App" / "ANYRUN-Sandbox-MDE-LA.json"
SANDBOX_PACKAGE = ROOT / "ANYRUN-Sandbox-MDE" / "Function App" / "ANYRUN-Sandbox-MDE-FA.zip"
FEEDS_FUNCTION = ROOT / "ANYRUN-TI-Feeds-MDE" / "Function App" / "ANYRUN-Feeds-MDE-FA.json"
FEEDS_LOGIC = ROOT / "ANYRUN-TI-Feeds-MDE" / "Logic App" / "ANYRUN-Feeds-MDE-LA.json"
FEEDS_PACKAGE = ROOT / "ANYRUN-TI-Feeds-MDE" / "Function App" / "ANYRUN-Feeds-MDE-FA.zip"
FEEDS_CONNECTOR = ROOT / "ANYRUN-TI-Feeds-MDE" / "src" / "ANYRUN-Feeds-MDE-FA" / "anyrun_connector.py"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DeploymentScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SCRIPT.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")

    def artifact_hash(self, connector, key):
        block = self.text.split(f"  {connector} = @{{", 1)[1].split("\n  }", 1)[0]
        match = re.search(rf'{key}Sha256 = "([0-9a-f]{{64}})"', block)
        self.assertIsNotNone(match, f"{connector}.{key}")
        return match.group(1)

    def test_script_exists_and_has_balanced_delimiters(self):
        self.assertTrue(SCRIPT.is_file())
        # A full parser is exercised in CI/Cloud Shell. Braces are still a useful
        # lightweight local guard; raw parentheses may occur in string literals.
        self.assertEqual(self.text.count("{"), self.text.count("}"))
        self.assertEqual(self.text.count("["), self.text.count("]"))

    def test_modes_and_parameter_validation(self):
        self.assertIn('[ValidateSet("Sandbox", "Feeds")]', self.text)
        self.assertIn('[ValidateSet("Audit", "Block", "Disabled")]', self.text)
        self.assertNotIn('[ValidateSet("Allowed",', self.text)
        self.assertIn('[ValidateRange(1, 100)]', self.text)
        self.assertIn("function Assert-GuidValue", self.text)
        self.assertIn("function Assert-LogicAppName", self.text)

    def test_feeds_installer_requires_direct_api_key_without_source_switch(self):
        self.assertNotIn('Sentinel', self.text)
        self.assertNotIn('IndicatorSource', self.text)
        self.assertNotIn('Sentinel', self.doc)
        self.assertIn('Read-RequiredSecret "  ANY.RUN TI Feeds API key (without a prefix)"', self.text)
        self.assertIn('$parameters.anyrunApiKey = $ApiKey', self.text)

    def test_feeds_first_run_schedule_matches_azureapp(self):
        standalone = json.loads(FEEDS_LOGIC.read_text(encoding="utf-8"))
        marketplace = json.loads(
            (ROOT.parent / "AzureApp" / "1.1.4" / "TI-Feeds" / "mainTemplate.json")
            .read_text(encoding="utf-8")
        )
        def trigger(template):
            workflow = next(
                resource for resource in template["resources"]
                if resource["type"] == "Microsoft.Logic/workflows"
            )
            self.assertEqual(workflow["properties"]["state"], "Enabled")
            return workflow["properties"]["definition"]["triggers"]["Recurrence"]
        self.assertEqual(trigger(standalone), trigger(marketplace))
        self.assertNotIn("startTime", trigger(standalone)["recurrence"])

    def test_sandbox_indicator_action_is_wired_through_deployment(self):
        template = json.loads(SANDBOX_FUNCTION.read_text(encoding="utf-8"))
        parameter = template["parameters"]["DefenderIndicatorAction"]
        self.assertEqual(parameter["defaultValue"], "Audit")
        self.assertEqual(parameter["allowedValues"], ["Audit", "Block", "Disabled"])
        site = next(
            resource for resource in template["resources"]
            if resource["type"] == "Microsoft.Web/sites"
        )
        settings = {
            item["name"]: item["value"]
            for item in site["properties"]["siteConfig"]["appSettings"]
        }
        self.assertEqual(
            settings["DefenderIndicatorAction"],
            "[parameters('DefenderIndicatorAction')]",
        )
        # Microsoft requires GenerateAlert for Audit; there is no opt-out switch.
        self.assertNotIn("DefenderIndicatorGenerateAlert", template["parameters"])
        self.assertNotIn("DefenderIndicatorGenerateAlert", settings)
        self.assertNotIn("DefenderIndicatorGenerateAlert", self.text)
        self.assertRegex(self.text, r"DefenderIndicatorAction\s+= \$DefenderIndicatorAction")
        self.assertIn('-DefenderIndicatorAction Disabled applies only to Sandbox', self.text)
        feeds = json.loads(FEEDS_FUNCTION.read_text(encoding="utf-8"))
        self.assertEqual(feeds["parameters"]["DefenderIndicatorAction"]["allowedValues"], ["Audit", "Block"])
        marketplace = json.loads(
            (ROOT.parent / "AzureApp" / "1.1.4" / "Sandbox" / "mainTemplate.json").read_text(encoding="utf-8"))
        self.assertEqual(marketplace["parameters"]["defenderIndicatorAction"]["allowedValues"], ["Audit", "Block", "Disabled"])
        self.assertNotIn("defenderIndicatorGenerateAlert", marketplace["parameters"])

    def test_sandbox_privacy_is_explicit_and_configurable(self):
        logic = json.loads(SANDBOX_LOGIC.read_text(encoding="utf-8"))
        privacy = logic["parameters"]["analysisPrivacyType"]
        self.assertEqual(privacy["defaultValue"], "bylink")
        self.assertEqual(privacy["allowedValues"], ["bylink", "owner"])
        self.assertIn('[ValidateSet("bylink", "owner")]', self.text)
        self.assertIn("analysisPrivacyType = $SandboxAnalysisPrivacyType", self.text)

    def test_evidence_lifecycle_is_only_enabled_for_installer_created_storage(self):
        template = json.loads(SANDBOX_FUNCTION.read_text(encoding="utf-8"))
        policy = next(
            resource for resource in template["resources"]
            if resource["type"] == "Microsoft.Storage/storageAccounts/managementPolicies"
        )
        self.assertEqual(
            policy["condition"],
            "[parameters('ConfigureEvidenceLifecyclePolicy')]",
        )
        self.assertFalse(
            template["parameters"]["ConfigureEvidenceLifecyclePolicy"]["defaultValue"]
        )
        self.assertIn("Created                = $created", self.text)
        self.assertIn("-ConfigureLifecyclePolicy ([bool]$storage.Created)", self.text)
        self.assertIn(
            "$parameters.ConfigureEvidenceLifecyclePolicy = $ConfigureLifecyclePolicy",
            self.text,
        )

    def test_secret_inputs_are_secure_strings(self):
        for name in ("SandboxClientSecret", "SandboxApiKey", "FeedsClientSecret", "FeedsApiKey"):
            self.assertRegex(self.text, rf"\[SecureString\]\${name}\b")
        self.assertIn("Read-Host $Prompt -AsSecureString", self.text)
        self.assertNotIn("Write-Host $result.SecretText", self.text)

    def test_default_secret_lifetime_is_six_months(self):
        self.assertIn("[int]$SecretLifetimeMonths = 6", self.text)
        self.assertIn("six months by default", self.doc)

    def test_cloud_shell_module_loader_avoids_mixed_az_bundle(self):
        body = self.text.split("function Get-ModuleInstallationRoot", 1)[1]
        body = body.split("function ConvertFrom-AzRestContent", 1)[0]
        self.assertIn('$anchorName = if ($Name -like "Az.*")', body)
        self.assertIn('"Az.Accounts"', body)
        self.assertIn("RequiredVersion = $selected.Version", body)
        self.assertNotIn("Import-Module -Name $Name -MinimumVersion", body)

    def test_graph_session_is_disconnected_only_when_owned(self):
        self.assertIn("$script:GraphSessionOwned = $true", self.text)
        final = self.text.rsplit("} finally {", 1)[1]
        self.assertIn("if ($script:GraphSessionOwned)", final)
        self.assertIn("Disconnect-MgGraph", final)

    def test_reviewed_repository_ref_is_resolved_to_commit(self):
        self.assertIn('$Repository = "yaestkit/anyrun-integration-microsoft"', self.text)
        self.assertIn('$RepositoryRef = "refs/heads/asyncv2"', self.text)
        self.assertNotRegex(self.text, r"\[string\]\$Repository(Ref)?\s*=")
        body = self.text.split("function Resolve-RepositoryCommit", 1)[1]
        body = body.split("function Get-VerifiedRemoteFile", 1)[0]
        self.assertIn("api.github.com/repos/$RepositoryName/commits/$encodedRef", body)
        self.assertIn("^[0-9a-fA-F]{40}$", body)
        self.assertIn("$script:ResolvedRepositoryRef = Resolve-RepositoryCommit", self.text)

    def test_remote_files_require_allowlisted_https_and_sha256(self):
        body = self.text.split("function Get-VerifiedRemoteFile", 1)[1]
        body = body.split("function Show-ResourceGroupWriteAccess", 1)[0]
        self.assertIn("raw.githubusercontent.com", body)
        self.assertIn("Get-FileHash", body)
        self.assertIn("SHA-256 mismatch", body)
        self.assertNotIn("AllowUnverifiedArtifacts", self.text)

    def test_built_in_hashes_match_all_reviewed_artifacts(self):
        expected = {
            ("Sandbox", "Package"): SANDBOX_PACKAGE,
            ("Feeds", "Package"): FEEDS_PACKAGE,
            ("Sandbox", "FunctionTemplate"): SANDBOX_FUNCTION,
            ("Sandbox", "LogicTemplate"): SANDBOX_LOGIC,
            ("Feeds", "FunctionTemplate"): FEEDS_FUNCTION,
            ("Feeds", "LogicTemplate"): FEEDS_LOGIC,
        }
        for (connector, key), path in expected.items():
            self.assertEqual(self.artifact_hash(connector, key), sha256(path), f"{connector}.{key}")

    def test_powershell_and_azureapp_share_runtime_packages_and_source(self):
        for kind, connector, folder in (
            ("Sandbox", "ANYRUN-Sandbox-MDE", "Sandbox"),
            ("Feeds", "ANYRUN-TI-Feeds-MDE", "TI-Feeds"),
        ):
            with self.subTest(connector=connector):
                name = f"ANYRUN-{kind}-MDE-FA.zip"
                standalone = ROOT / connector / "Function App" / name
                azureapp = ROOT.parent / "AzureApp" / "1.1.4" / folder / "artifacts" / name
                self.assertEqual(standalone.read_bytes(), azureapp.read_bytes())
                with zipfile.ZipFile(standalone) as package:
                    self.assertIsNone(package.testzip())
                    for member in package.infolist():
                        if member.is_dir():
                            continue
                        self.assertEqual(package.read(member),
                                         (ROOT / connector / "src" / member.filename).read_bytes(),
                                         member.filename)

    def test_function_dependencies_are_pinned_and_hashed(self):
        for connector in ("ANYRUN-Sandbox-MDE", "ANYRUN-TI-Feeds-MDE"):
            source = ROOT / connector / "src"
            direct = (source / "requirements.in").read_text(encoding="utf-8")
            locked = (source / "requirements.txt").read_text(encoding="utf-8")
            self.assertTrue(all("==" in line for line in direct.splitlines() if line.strip()))
            self.assertIn("--hash=sha256:", locked)
            self.assertIn("azure-functions==1.25.0", locked)
            self.assertIn("anyrun-sdk==1.14.19", locked)

    def test_checked_in_package_uris_are_not_commit_pinned(self):
        expected = "raw.githubusercontent.com/yaestkit/anyrun-integration-microsoft/refs/heads/asyncv2"
        for path in (SANDBOX_FUNCTION, FEEDS_FUNCTION):
            template = path.read_text(encoding="utf-8")
            self.assertIn(expected, template)
            self.assertNotRegex(template, r"raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/")

    def test_package_parameter_is_pinned_to_resolved_commit(self):
        body = self.text.split("function Get-ConnectorArtifacts", 1)[1]
        body = body.split("function Get-FunctionTemplateParameters", 1)[0]
        self.assertIn("$script:ResolvedRepositoryRef", body)
        self.assertIn("Get-VerifiedRemoteFile", body)
        self.assertIn("[IO.Compression.ZipFile]::OpenRead", body)
        self.assertIn("packageUri                   = $Names.PackageUri", self.text)
        for path in (SANDBOX_FUNCTION, FEEDS_FUNCTION):
            template = json.loads(path.read_text(encoding="utf-8"))
            extension = next(r for r in template["resources"] if r["type"] == "Microsoft.Web/sites/extensions")
            self.assertEqual(extension["properties"]["packageUri"], "[parameters('packageUri')]")

    def test_reviewed_templates_are_deployed_without_rewriting(self):
        self.assertNotIn("ConvertTo-Json -Depth 100 | Set-Content", self.text)
        self.assertNotIn("Set-FunctionSupportingResourceNames", self.text)
        for path in (SANDBOX_FUNCTION, FEEDS_FUNCTION):
            template = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(any(r["type"] == "Microsoft.Resources/deploymentScripts" for r in template["resources"]))
            for name in ("hostingPlanName", "appInsightsName"):
                self.assertEqual(template["parameters"][name]["defaultValue"], "[parameters('functionAppName')]")
            plan = next(r for r in template["resources"] if r["type"] == "Microsoft.Web/serverfarms")
            insights = next(r for r in template["resources"] if r["type"] == "Microsoft.Insights/components")
            self.assertEqual(plan["name"], "[parameters('hostingPlanName')]")
            self.assertEqual(insights["name"], "[parameters('appInsightsName')]")
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"resourceId\('Microsoft\.(Web/serverfarms|Insights/components)', parameters\('functionAppName'\)\)")

    def test_app_registration_binding_is_marked_and_validated(self):
        self.assertIn("anyrun-mde-installer:v1", self.text)
        self.assertIn("Unmarked Function binding cannot be adopted implicitly", self.text)
        self.assertIn("declares permissions to other APIs", self.text)
        self.assertIn("app-role assignments outside WindowsDefenderATP", self.text)
        self.assertIn("Non-interactive reuse of an App Registration", self.text)

    def test_permission_grant_requires_explicit_confirmation(self):
        body = self.text.split("function Confirm-DefenderPermissionGrant", 1)[1]
        body = body.split("function Ensure-ConnectorIdentity", 1)[0]
        self.assertIn("ApproveDefenderPermissions", body)
        self.assertIn("Non-interactive consent requires", body)
        self.assertIn("Grant these Defender application permissions?", body)

    def test_exact_least_privilege_roles(self):
        roles = {
            "Alert.ReadWrite.All", "Machine.LiveResponse",
            "Machine.ReadWrite.All", "Ti.ReadWrite", "Library.Manage",
        }
        sandbox = self.text.split("$sandboxRoles = @(", 1)[1].split(")", 1)[0]
        quoted = set(re.findall(r'"([A-Za-z.]+)"', sandbox))
        self.assertEqual(roles, quoted)
        configured = self.text.split("$sandboxRoles = @(", 1)[1].split("function Write-Banner", 1)[0]
        for role in ("Ti.ReadWrite.All", "Ti.Read.All", "Alert.Read.All"):
            self.assertNotIn(f'"{role}"', configured)

    def test_resource_group_writer_review_precedes_entra_mutation(self):
        execution = self.text.split('Write-Banner "ANY.RUN', 1)[1]
        self.assertLess(execution.index("Show-ResourceGroupWriteAccess"), execution.index("Ensure-ConnectorIdentity"))
        self.assertIn("Treat this resource group as privileged", self.text)

    def test_placeholder_exists_for_logic_only_preflight(self):
        initialization = "$placeholderSecret = ConvertTo-SecureValue -Value \"preflight-placeholder\""
        self.assertIn(initialization, self.text)
        self.assertLess(self.text.index(initialization),
                        self.text.index("if (-not $SkipFunctionApp) {\n  Test-ArmDeployment"))

    def test_function_templates_are_hardened_and_nested_rbac_is_scoped(self):
        for path in (SANDBOX_FUNCTION, FEEDS_FUNCTION):
            template = json.loads(path.read_text(encoding="utf-8"))
            resources = template["resources"]
            site = next(r for r in resources if r["type"] == "Microsoft.Web/sites")
            self.assertTrue(site["properties"]["httpsOnly"])
            self.assertEqual(site["properties"]["siteConfig"]["minTlsVersion"], "1.2")
            policies = [r for r in resources if r["type"] == "Microsoft.Web/sites/basicPublishingCredentialsPolicies"]
            self.assertEqual(len(policies), 2)
            self.assertTrue(any("'ftp'" in r["name"] for r in policies))
            self.assertTrue(any("'scm'" in r["name"] for r in policies))
            self.assertTrue(all(r["properties"]["allow"] is False for r in policies))
            storage = next(r for r in resources if r["type"] == "Microsoft.Storage/storageAccounts")
            self.assertEqual(storage["properties"]["minimumTlsVersion"], "TLS1_2")
            self.assertFalse(storage["properties"]["allowBlobPublicAccess"])
            nested = next(r for r in resources if r["type"] == "Microsoft.Resources/deployments")
            assignment = next(r for r in nested["properties"]["template"]["resources"] if r["type"] == "Microsoft.Authorization/roleAssignments")
            self.assertEqual(assignment["properties"]["principalType"], "ServicePrincipal")
            self.assertIn("Microsoft.Storage/storageAccounts", assignment["scope"])
            # Flex Consumption deployment storage needs Storage Blob Data Contributor.
            self.assertEqual(template["variables"]["storageRoleDefinitionId"], "ba92f5b4-2d11-453d-a403-e96b0029c9fe")

    def test_function_http_triggers_are_post_only(self):
        for connector in ("ANYRUN-Sandbox-MDE", "ANYRUN-TI-Feeds-MDE"):
            function_dir = "ANYRUN-Sandbox-MDE-FA" if connector == "ANYRUN-Sandbox-MDE" else "ANYRUN-Feeds-MDE-FA"
            path = ROOT / connector / "src" / function_dir / "function.json"
            config = json.loads(path.read_text(encoding="utf-8"))
            trigger = next(b for b in config["bindings"] if b["type"] == "httpTrigger")
            self.assertEqual(trigger["methods"], ["post"])

    def test_confidence_key_is_consistent(self):
        logic = json.loads(FEEDS_LOGIC.read_text(encoding="utf-8"))
        workflow = next(r for r in logic["resources"] if r["type"] == "Microsoft.Logic/workflows")
        body = workflow["properties"]["definition"]["actions"]["ANYRUNFeeds-AnyRunFeeds"]["inputs"]["body"]
        self.assertEqual(set(body), {"feed_fetch_depth", "minimum_confidence_threshold"})
        source = FEEDS_CONNECTOR.read_text(encoding="utf-8")
        self.assertIn("minimum_confidence_threshold", source)
        self.assertNotRegex(source, r"minimum_confidence(?!_threshold)")
        self.assertIn("minimum_confidence_threshold = $FeedsMinimumConfidence", self.text)

    def test_feeds_action_does_not_allow_allowed_value(self):
        template = FEEDS_FUNCTION.read_text(encoding="utf-8")
        combined = self.text + template + self.doc
        self.assertNotIn('"Allowed"', combined)
        self.assertNotIn("accepts `Allowed`", combined)

    def test_feeds_smoke_test_records_failure_in_summary(self):
        verification = self.text.split('Write-Phase "5" "Verification"', 1)[1]
        self.assertIn('catch { $verificationFailures.Add("Feeds Logic App smoke test failed:', verification)

    def test_onedeploy_retries_are_narrowed_to_transient_failures(self):
        body = self.text.split("function Invoke-ArmDeployment", 1)[1]
        body = body.split("function Assert-FunctionName", 1)[0]
        self.assertIn("AuthorizationPermissionMismatch", body)
        self.assertIn("PrincipalNotFound", body)
        self.assertIn("$packageRbacNotReady", body)
        self.assertIn("$transientOneDeployFailure", body)
        self.assertNotIn("$retryable = $principalNotReady -or $packageRbacNotReady -or $onedeployFailed", body)

    def test_legacy_role_cleanup_matches_name_and_principal(self):
        body = self.text.split("function Remove-LegacyStorageRoleAssignment", 1)[1]
        body = body.split("function Get-ConnectorArtifacts", 1)[0]
        self.assertIn("sites/$($FunctionAppName)?api-version=2024-11-01", body)
        self.assertNotRegex(body, r"\$[A-Za-z_][A-Za-z0-9_]*\?")
        self.assertIn('Get-ObjectPropertyValue -InputObject $site -Name "identity"', body)
        self.assertIn("Get-ObjectPropertyValue -InputObject $identity -Name 'principalId'", body)
        self.assertNotIn("$site.identity.principalId", body)
        self.assertIn("$legacyNames -contains $_.RoleAssignmentName", body)
        self.assertIn("$_.ObjectId.ToString() -eq $principalId", body)

    def test_superseded_owner_role_is_removed_after_contributor_deployment(self):
        body = self.text.split("function Remove-LegacyStorageRoleAssignment", 1)[1]
        body = body.split("function Get-ConnectorArtifacts", 1)[0]
        self.assertIn("if ($SupersededOwner)", body)
        self.assertIn("$script:LegacyStorageBlobDataOwnerRoleId", body)
        flow = self.text.split('Write-Phase "3" "Function App"', 1)[1].split('Write-Phase "4"', 1)[0]
        self.assertLess(flow.index("Invoke-ArmDeployment"), flow.index("-SupersededOwner"))

    def test_azure_rest_errors_are_reported_with_status(self):
        body = self.text.split("function Invoke-AzRestJson", 1)[1].split("function Get-ObjectPropertyValue", 1)[0]
        self.assertIn("returned HTTP $status", body)
        for caller in ("function Assert-FunctionAppNameAvailable", "function Test-EffectiveRoleAssignmentPermission",
                       "function Get-ExistingFunctionConfiguration"):
            function = self.text.split(caller, 1)[1].split("\nfunction ", 1)[0]
            self.assertIn("Invoke-AzRestJson", function, caller)
            self.assertNotIn("ConvertFrom-AzRestContent -Response (Invoke-AzRestMethod", function, caller)

    def test_dangerous_tenant_wide_settings_are_not_changed(self):
        self.assertNotIn("Set-MpPreference", self.text)
        self.assertNotIn("Set-MgDeviceManagement", self.text)
        self.assertIn("does not change tenant-wide Defender", self.doc)


if __name__ == "__main__":
    unittest.main()

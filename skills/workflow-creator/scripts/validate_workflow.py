#!/usr/bin/env python3
"""
Workflow validator

Validates workflow schema and instructions files.
"""

import json
import sys
from pathlib import Path


def validate_schema(schema_path):
    """Validate workflow schema JSON."""
    errors = []
    warnings = []

    # Check file exists
    if not schema_path.exists():
        errors.append(f"Schema file not found: {schema_path}")
        return errors, warnings

    # Load and parse JSON
    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON: {e}")
        return errors, warnings
    except Exception as e:
        errors.append(f"Error reading file: {e}")
        return errors, warnings

    # Validate required top-level fields
    required_fields = ['workflow_name', 'workflow_display_name', 'description',
                      'version', 'created_date', 'parameters', 'steps']

    for field in required_fields:
        if field not in schema:
            errors.append(f"Missing required field: {field}")

    if errors:
        return errors, warnings

    # Validate workflow_name format
    name = schema['workflow_name']
    if not name.islower() or not all(c.isalnum() or c == '-' for c in name):
        errors.append(f"workflow_name must be lowercase-with-hyphens: {name}")

    # Validate parameters
    if not isinstance(schema['parameters'], list):
        errors.append("parameters must be a list")
    else:
        param_names = set()
        for i, param in enumerate(schema['parameters']):
            # Check required parameter fields
            required_param_fields = ['name', 'display_name', 'description', 'type', 'required']
            for field in required_param_fields:
                if field not in param:
                    errors.append(f"Parameter {i}: Missing required field '{field}'")

            # Check parameter name uniqueness
            if 'name' in param:
                if param['name'] in param_names:
                    errors.append(f"Duplicate parameter name: {param['name']}")
                param_names.add(param['name'])

                # Validate parameter name format
                if not param['name'].islower() or not all(c.isalnum() or c == '_' for c in param['name']):
                    errors.append(f"Parameter name must be lowercase_with_underscores: {param['name']}")

            # Validate parameter type
            if 'type' in param:
                valid_types = ['string', 'integer', 'float', 'boolean', 'select', 'files']
                if param['type'] not in valid_types:
                    errors.append(f"Parameter {param.get('name', i)}: Invalid type '{param['type']}'. Must be one of: {valid_types}")

                # Check for options if type is select
                if param['type'] == 'select' and 'options' not in param:
                    errors.append(f"Parameter {param.get('name', i)}: 'select' type requires 'options' field")

                # Check for files type validation
                if param['type'] == 'files':
                    if 'default' in param and not isinstance(param['default'], list):
                        errors.append(f"Parameter {param.get('name', i)}: 'files' type default value must be an array")
                    elif 'default' in param:
                        for file_item in param['default']:
                            if not isinstance(file_item, str):
                                errors.append(f"Parameter {param.get('name', i)}: 'files' type default array must contain only strings")
                            elif file_item.startswith("uploaded_files/"):
                                bare_name = file_item[len("uploaded_files/"):]
                                errors.append(
                                    f"Parameter {param.get('name', i)}: file default '{file_item}' must be just the filename "
                                    f"('{bare_name}'), not the full path. Remove the 'uploaded_files/' prefix."
                                )

            # Check default value presence for ALL parameters (required and optional)
            if 'default' not in param:
                errors.append(f"Parameter {param.get('name', i)}: All parameters must have a 'default' value (required={param.get('required', True)})")

    # Validate steps
    if not isinstance(schema['steps'], list):
        errors.append("steps must be a list")
    elif len(schema['steps']) == 0:
        errors.append("Workflow must have at least one step")
    else:
        step_numbers = set()
        step_names = set()
        param_names_list = [p['name'] for p in schema['parameters'] if 'name' in p]

        for i, step in enumerate(schema['steps']):
            # Check required step fields
            required_step_fields = ['step_number', 'step_name', 'display_name', 'description']
            for field in required_step_fields:
                if field not in step:
                    errors.append(f"Step {i}: Missing required field '{field}'")

            # Check step number uniqueness and sequence
            if 'step_number' in step:
                if step['step_number'] in step_numbers:
                    errors.append(f"Duplicate step_number: {step['step_number']}")
                step_numbers.add(step['step_number'])

            # Check step name uniqueness and format
            if 'step_name' in step:
                if step['step_name'] in step_names:
                    errors.append(f"Duplicate step_name: {step['step_name']}")
                step_names.add(step['step_name'])

                if not step['step_name'].islower() or not all(c.isalnum() or c == '_' for c in step['step_name']):
                    errors.append(f"Step name must be lowercase_with_underscores: {step['step_name']}")

            # Validate parameters_used references
            if 'parameters_used' in step:
                if not isinstance(step['parameters_used'], list):
                    errors.append(f"Step {step.get('step_name', i)}: parameters_used must be a list")
                else:
                    for param_ref in step['parameters_used']:
                        if param_ref not in param_names_list:
                            errors.append(f"Step {step.get('step_name', i)}: Unknown parameter '{param_ref}'")

        # Check step numbers are sequential starting from 1
        if step_numbers:
            expected = set(range(1, len(schema['steps']) + 1))
            if step_numbers != expected:
                warnings.append(f"Step numbers should be sequential from 1 to {len(schema['steps'])}")

    return errors, warnings


def validate_instructions(instructions_path, schema):
    """Validate workflow instructions file."""
    errors = []
    warnings = []

    # Check file exists
    if not instructions_path.exists():
        errors.append(f"Instructions file not found: {instructions_path}")
        return errors, warnings

    # Read instructions
    try:
        with open(instructions_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        errors.append(f"Error reading instructions: {e}")
        return errors, warnings

    # Check for parameter references
    param_names = [p['name'] for p in schema.get('parameters', []) if 'name' in p]
    for param_name in param_names:
        if f"{{{param_name}}}" not in content:
            warnings.append(f"Parameter '{param_name}' not referenced in instructions")

    # Check for step headers
    steps = schema.get('steps', [])
    for step in steps:
        step_name = step.get('display_name', '')
        if step_name and step_name not in content:
            warnings.append(f"Step '{step_name}' not found in instructions")

    # Cross-validate step count between schema and SKILL.md
    import re
    md_step_headers = re.findall(r'^###\s+Step\s+\d+', content, re.MULTILINE)
    md_step_count = len(md_step_headers)
    json_step_count = len(steps)
    if md_step_count > 0 and json_step_count != md_step_count:
        errors.append(
            f"Step count mismatch: workflow_schema.json has {json_step_count} step(s) "
            f"but SKILL.md has {md_step_count} step section(s). Both files must be in sync."
        )

    # Check for basic structure
    if '## Parameters' not in content and len(param_names) > 0:
        warnings.append("Instructions should include a '## Parameters' section")

    if '## Steps' not in content and len(steps) > 0:
        warnings.append("Instructions should include a '## Steps' section")

    return errors, warnings


def validate_workflow(workflow_name):
    """Validate a complete workflow."""
    print(f"=== Validating workflow: {workflow_name} ===\n")

    # Find schema file in /workspace/workflow/{workflow_name}/
    schema_path = Path(f"/workspace/workflow/{workflow_name}/workflow_schema.json")
    if not schema_path.exists():
        # Fallback: try relative path from current directory
        schema_path = Path.cwd() / "workflow" / workflow_name / "workflow_schema.json"

    # Validate schema
    print("Validating schema...")
    schema_errors, schema_warnings = validate_schema(schema_path)

    if schema_errors:
        print("\n❌ Schema Errors:")
        for error in schema_errors:
            print(f"  - {error}")

    if schema_warnings:
        print("\n⚠️  Schema Warnings:")
        for warning in schema_warnings:
            print(f"  - {warning}")

    # Load schema for instructions validation
    schema = {}
    if not schema_errors:
        try:
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema = json.load(f)
        except:
            pass

    # Find and validate instructions in /workspace/workflow/{workflow_name}/
    instructions_path = Path(f"/workspace/workflow/{workflow_name}/SKILL.md")
    if not instructions_path.exists():
        # Fallback: try relative path from current directory
        instructions_path = Path.cwd() / "skills" / workflow_name / "SKILL.md"

    if instructions_path.exists():
        print("\nValidating instructions...")
        inst_errors, inst_warnings = validate_instructions(instructions_path, schema)

        if inst_errors:
            print("\n❌ Instructions Errors:")
            for error in inst_errors:
                print(f"  - {error}")

        if inst_warnings:
            print("\n⚠️  Instructions Warnings:")
            for warning in inst_warnings:
                print(f"  - {warning}")
    else:
        print(f"\n⚠️  Instructions file not found: {instructions_path}")
        inst_errors = []

    # Summary
    total_errors = len(schema_errors) + len(inst_errors) if instructions_path.exists() else len(schema_errors)
    total_warnings = len(schema_warnings) + len(inst_warnings) if instructions_path.exists() else len(schema_warnings)

    print(f"\n{'='*50}")
    if total_errors == 0:
        print("✅ Validation passed!")
        if total_warnings > 0:
            print(f"⚠️  {total_warnings} warning(s) found")
        return True
    else:
        print(f"❌ Validation failed with {total_errors} error(s)")
        if total_warnings > 0:
            print(f"⚠️  {total_warnings} warning(s) found")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: validate_workflow.py <workflow_name>")
        print("\nExample:")
        print("  validate_workflow.py research-to-presentation")
        sys.exit(1)

    workflow_name = sys.argv[1]
    success = validate_workflow(workflow_name)
    sys.exit(0 if success else 1)

# SIG # Begin Windows Authenticode signature block
# MIInKAYJKoZIhvcNAQcCoIInGTCCJxUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQse8BENmB6EqSR2hd
# JGAGggIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCxfVS1Xjwbxdd+
# dJivM81n9ZI7NO8iXCUIEG2IfcgqpKCCDLowggX1MIID3aADAgECAhMzAAACHU0Z
# yE7XD1dIAAAAAAIdMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBD
# b2RlIFNpZ25pbmcgUENBIDIwMjQwHhcNMjYwNDE2MTg1OTQzWhcNMjcwNDE1MTg1
# OTQzWjB0MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYD
# VQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQDQvewXxx9gZZFC6Ys1WBay8BJ8kGA4JQnH5CMafqOASlTpK9H8
# o5ZXTXt0caVQTNMUPt445wXYD+dFtaKWTwDn1I52oUSrC9vJin1Gsqt+zyKJL5Dg
# 3eQXbQNR61DmMy20GLTIO3SFed9Rfi/ophgCLGFLDR3r0KvHjwMb/jYWS0celV/4
# Lz27LfAekm8v9E5IXaeiXbAUYZKK090n4CVl3JBtbN+9DtI9SNu/yjvozW52/u7R
# X/Ttpa/KDlpuokZ+Zcbvmtd9ur9gFLvZzh41o9MsE/clQtdaFWGvuo6Jua/ntpgk
# ey3E5/vBFe+MJPG6phdnuo6r57ZudCudiI1bAgMBAAGjggGbMIIBlzAOBgNVHQ8B
# Af8EBAMCB4AwHwYDVR0lBBgwFgYKKwYBBAGCN0wIAQYIKwYBBQUHAwMwHQYDVR0O
# BBYEFH6QuMwqcPG0hQlQ6c5jCtTTLrVeMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQL
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTIzMDAxMis1MDc1NTkw
# HwYDVR0jBBgwFoAUf1k/VCHarU/vBeXmo9ctBpQSCDEwYAYDVR0fBFkwVzBVoFOg
# UYZPaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDI0LmNybDBtBggrBgEFBQcBAQRh
# MF8wXQYIKwYBBQUHMAKGUWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y2VydHMvTWljcm9zb2Z0JTIwQ29kZSUyMFNpZ25pbmclMjBQQ0ElMjAyMDI0LmNy
# dDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBKTbYOjzwTG/DXGaz9
# s6+fQeaTtDcFmMY+5UyVFCyj7Pv+5i37qfX8lSL/tBIfYQfWsMuBQlfZurJD6r4H
# VJ2CeH+1fgiq8dcHdVKoZ3Sa2qXoX3cq9iS8cVb06B7+5/XJ7I0OxHH9fDsvJ3T3
# w5V/ZtAIFmLrl+P0CtG+92uzRsn0nTbdFjOkLMLWPLAU3THohKRlSEMgFJpPkm5n
# 5UAZ35xX6FWCrDLsSKb555bTifwa8mJBwdlof0bmfYidH+dxZ1FdDxvLnNl9zeKs
# A4kejaaIqqIPguhwAti5Ql7BlTNoJNwxCvBmqW2MQLnCkYN/VVUsR3V2x/rcTNzo
# Bf/Z/SpROvdaA2ZOOd1uioXJt3tdLQ7vHpqpib0KfWr/FWXW10q38VxfCnRQBqzb
# SuztR7nEMuzX7Ck+B/XaPDXd1qh72+QYyB0Z2VzWmO9zsnb9Uq/dwu8LGeQqnyu6
# 7SDGACvnXii2fb9+US492VTnXSnFKyqwgzUyFMtZK1/sHYTv6bG4TtQUygQxTN+Z
# V+aJIlKO2MqZ7bKrAnOzS9m6NgoTdWOq11bTOZwKlIEV/EhV9SWkDmdpR/hPPT2v
# 6TEj4F8PT/zHjRezIU5c/DGlt/VhY/pK0XkJtEyMmmS1BMtjU/rqBZVMIm3dnxQs
# /TBByr+Cf8Z1r7aifQVQ+WSqzjCCBr0wggSloAMCAQICEzMAAAA5O7Y3Gb8GHWcA
# AAAAADkwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDExMB4XDTI0MDgwODIwNTQxOFoXDTM2MDMyMjIyMTMwNFow
# VzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEo
# MCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAyNDCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBANgBnB7jOMeqlRYHNa265v4IY9fH8TKh
# emHfPINe1gpLaV3dhg324WwH06LcHbpnsBukCDNitryo0dtS/EW6I/yEL/bLSY8h
# KpbfQuWusBPr9qazYcDxCW/qnjb5JsI1s8bNOg3bVATvQVL4tcf03aTycsz8QeCd
# M0l/yHRObJ9QqazM1r6VPEOJ7LL+uEEb73w6QCuhs89a1uv1zerOYMnsneRRwCbp
# yW11IcggU0cRKDDq1pjVJzIbIF6+oiXXbReOsgeI8zu1FyQfK0fVkaya8SmVHQ/t
# Of23mZ4W9k0Ri22QW9p3UgSC5OUDktKxxcCmGL6tXLfOGSWHIIV4YrTJTT6PNty5
# REojHJuZHArkF9VnHTERWoTjAzfI3kP+5b4alUdhgAZ7ttOu1bVnXfHaqPYl2rPs
# 20ji03LOVWsh/radgE17es5hL+t6lV0eVHrVhsssROWJuz2MXMCt7iw7lFPG9LXK
# Gjsmonn2gotGdHIuEg5JnJMJVmixd5LRlkmgYRZKzhxSCwyoGIq0PhaA7Y+VPct5
# pCHkijcIIDm0nlkK+0KyepolcqGm0T/GYQRMhHJlGOOmVQop36wUVUYklUy++vDW
# eEgEo4s7hxN6mIbf2MSIQ/iIfMZgJxC69oukMUXCrOC3SkE/xIkgpfl22MM1itkZ
# 35nNXkMolU1lAgMBAAGjggFOMIIBSjAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGC
# NxUBBAMCAQAwHQYDVR0OBBYEFH9ZP1Qh2q1P7wXl5qPXLQaUEggxMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# ci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0MjAx
# MV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAx
# MV8yMDExXzAzXzIyLmNydDANBgkqhkiG9w0BAQwFAAOCAgEAFJQfOChP7onn6fLI
# MKrSlN1WYKwDFgAddymOUO3FrM8d7B/W/iQ6DxXsDn7D5W4wMwYeLystcEqfkjz4
# NURRgazyMu5yRzQh4LqjA4tStTcJh1opExo7nn5PuPBYnbu0+THSuVHTe0VTTPVh
# ily/piFrDo3axQ9P4C+Ol5yet+2gTfekICS5xS+cYfSIvgn0JksVBVMYVI5QFu/q
# hnLhsEFEUzG8fvv0hjgkO+lkpV9ty6GkN4vdnd7ya6Q6aR9y34aiM1qmxaxBi6OU
# nyNl6fkuun/diTFnYDLTppOkr/mg5WSfCiDVMNCxtj4wPKC5OmHm1DQIt/MNokbb
# H3UGsFP1QbzsLocuSqLCvH09Io3fDPTmscR9Y75G4qX7RTX8AdBPo0I6OEojf39z
# uFZt0qOHm65YWQE69cZM2ueE1MB05dNNgHK9gTE7zKvK/fg8B2qjW88MT/WF5V5u
# vZGtqa9FSL2RazArA+rDPuf6JGYz4HpgMZHB4S6szWSKYBv0VisCzfxgeU+dquXW
# 9bd0auYlOB58DPcOYKdc3Se94g+xL4pcEhbB54JOgAkwYTu/9dLeH2pDqeJZAABV
# DWRQCaXfO5LgyKwKCLYXpigrZYCjUSBcr+Ve8PFWMhVTQl0v4q8J/AUmQN5W4n10
# 1cY2L4A7GTQG1h32HHAvfQESWP0xghnEMIIZwAIBATBuMFcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jv
# c29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMjQCEzMAAAIdTRnITtcPV0gAAAAAAh0w
# DQYJYIZIAWUDBAIBBQCggZAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwLwYJ
# KoZIhvcNAQkEMSIEIKahocRHtIsPDeOuPC4J5mI3WasD9bNaGQi/zlLmh+XUMEIG
# CisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAvam+El6ZnZzav1LO
# j51nGdFhjC8FXfZe8r+m9JaryQtUnBvPGb3MtdyeYIL9PZ5kpSamSFyDvCRXM40d
# 3sTNGXauQnxdg04jYswTTTHNdePo1yEt0j7qsk1drPbEYx/TOA0FjAgxRdObzvmn
# cE1RkiDFXNRzsXG6/VqqREeVB/2GpcCPvPsf2/G3H0DSNiFec7vgWP3bLA+iYoIb
# HKf2KiZeFVA0HzYcMx7mlAr7paOQwskSE2dcAl2m1lAN36SCJe4p2uYaQ6RU9lpg
# cCPuzeWy2NyyKrYYSPeup2mhLG1zGLess6mG2jr7RxjHTpdfJS5GJ+5W/G+a5w+T
# VMOS3qGCF5QwgheQBgorBgEEAYI3AwMBMYIXgDCCF3wGCSqGSIb3DQEHAqCCF20w
# ghdpAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEEggE9
# MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAXtke3BVAzoagL
# XfUWyKBfgKlYkdUnVXYysyfgjkyjaAIGaqmsnLRyGBMyMDI2MTAwOTA1MjQ1NS4x
# NDZaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScw
# JQYDVQQLEx5uU2hpZWxkIFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHqMIIHIDCCBQigAwIBAgIT
# MwAAAiWAxzfGzap3SQABAAACJTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNjAyMTkxOTQwMDFaFw0yNzA1MTcxOTQwMDFa
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCm
# 8RIP0eLA46VcCPovvmqsIlN6qkmz5IsHWmUU0neUqp8uGxadeo+SwWBCwQ5alZI/
# DNdpXfyiZLZR6XYgpRPFzepIl7OCDb4NtEskJCIZDkQMNwrH9YwUyu71GGigsLIx
# eleHtA3utoVTeHjS1b8UnwORRtknKkyrUArT6ZpB2rodIcmcLcv3x3wwgYlOs0FE
# g5EsVrZb7LNc/nd0bXDp+HTOWWui8eoTVwJeLxcVP869oF8li5SU81aa2tGJ6/Js
# ejiz9JMW8SJXKBT2DCXMOUkCsGjonPZRqfvoMSIQZgtaOTyAJlrvsy0TZ78XrGqo
# ygtQimQnbOAL4KNLSCuW5TZEQGTHLOQJGgggb3j5gKC778+RIPJA+n/hmHJ/x4qT
# /HTTPoVeMCcuBKWrQXR1+/pYau3Fwe0tWIyG+LWzkRr/ZNPPupcA2Yci3qn8HR9R
# wvQopqSNJwn2Ri6am8AQyfVVy/BBw0t6jpoRPjwKvuUjfCzpae6duOxQtQ1XDN9P
# A2yl9sDko/+AXV/SOe8ea8QoQcv3s3ErkG+Lp6hnvw6OMPian4ggNkRtgtB7ro1O
# iopOUXJn9Y5EO3JUAXNcuM9m+5My1VEuvGytgAH3uxmslTnW3YbrfazaySCSSnWk
# haOZ33hgbuUQfH7n2NFEAUc/cFzfmCQUikWisnJYywIDAQABo4IBSTCCAUUwHQYD
# VR0OBBYEFLE40qoXTuMHX3AfZUu1n8nx2h93MB8GA1UdIwQYMBaAFJ+nFV0AXmJd
# g/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGlt
# ZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUA
# A4ICAQAHnfc2yUyoHZbvvyVKFuXh5HxxHIvIaR9JWpIfITJlc/Ki03juR+vckzq3
# tp5fFH5LL7eIFXRIuoewMsvWeFrWufrrW4HhmhCwkqArfA1C0xk+HaYs2O48YSxM
# X9lgS1kTTIb3YsfoFdFpKurPf2nc2Yd4wLg+FgwmkxkeyE3MUKVna8SZeVpEjnS5
# ucFck4srPwK2ORAf70I23GGyPhqgIKZphNXhSscTAQsyIqB5GwDMdRV5LK37NfU4
# YmxvCYh3TFYE/Gh01Q6yJvf9HxiEZpwW+oUk0gruHobg3sgIR5rfgUo8l30vUnaD
# YMcPAClaFMC/QbHZSaUhWXZG1OOcMp0g9vYQNLDEqFX2jlquvzVSSwtHtm1KTldC
# jRED+kdCybcPxbPalwJigXc1BsI9CitnTf0ljwb9NkZ/JVI8/D62rXXzhz4F3u0i
# VGzwncGaxRxHG/Xv4nTrpkOeepoYbNBbMWS2G1qP3Xj7pVf0+4qRyAqJ0stjQjoV
# OJImVPWRjz5PR3Dn6adQVMBJDM6gDrj1rZTFVgCtTijqGZSGzvXpGkF3vYsyE6ZD
# ma/kGdiUe5saeI6lH66PiWWXgqxt7sy2Ezv0yIjSVv+eMOT2QMUiZ6WCc7gVtAmX
# pfeIus+NmgFvM+Ic1X58e4I9EL4ZSAidSpWW0GZTLNC02mryLjCCB3EwggVZoAMC
# AQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIy
# NVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9
# DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2
# Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N
# 7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXc
# ag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJ
# j361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjk
# lqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37Zy
# L9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M
# 269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLX
# pyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLU
# HMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode
# 2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYE
# FJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEB
# MEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# RG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEE
# AYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
# /zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEug
# SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
# AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt
# 4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsP
# MeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++
# Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9
# QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2
# wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aR
# AfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5z
# bcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nx
# t67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3
# Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+AN
# uOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/Z
# cGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNNMIICNQIBATCB+aGB0aSBzjCB
# yzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMc
# TWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBU
# U1MgRVNOOjg2MDMtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
# dGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBTb+bKOPAjCBflhzw5EXBuSWxe
# DqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3
# DQEBCwUAAgUA7nJ5yzAiGA8yMDI2MTAwODIwMjEzMVoYDzIwMjYxMDA5MjAyMTMx
# WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDucnnLAgEAMAcCAQACAhiyMAcCAQAC
# AhX4MAoCBQDuc8tLAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKg
# CjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAMQABard
# HlQRw0N5a3zCrwhoktQoYWz+OP2w8CpFK1gL4rRvAAgtdgYfyImIbMvpNy6I0XPn
# ESvwo+cn4uSUI22SaozIjfaxBkG34MSBZUHuy8FWi24Z5b/nC+rybnvhe5OiYmqL
# eQqJgcx71wvzzUufCUiLX8qW6s+ZeXQUmqRzEHvzoFe2YSbuC73nCpbdpGGwRHnE
# Xr+RPzkEWKORxbI1ogxF3M8frUOirNsSJu/2V4TmMDBhfP1iEN+v5GnVwu2JdxSR
# 0cuyb3mA/uPEeE/jfbtNuu6RVFyrIJDimQaFQmRzNmEqQBs5+DJzVU3zaI+gVg2H
# Rk+zZoMA1QXBrkoxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAiWAxzfGzap3SQABAAACJTANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAaaLvD
# mgXPeO/X02OePnR4lUhi35rn2X6TMC0QAthOszCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIFYN7oh6ON3y92CmAl/lF0CYwrjWWQP6dCUxajPSHKEQMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAIlgMc3xs2qd0kA
# AQAAAiUwIgQgzcRbqpIhcdX/xu1uCUUynG0Orhx0mTedn/r5DoOtKSowDQYJKoZI
# hvcNAQELBQAEggIAK4SZRHP4CqBDdq95OXbc06aI+DmxAc7W8IEUGqWoKeAL38yG
# EuybXDTWzwyxIWz1XDrb3k+y6a8B2iKiBPZrgwPIXHv66GXBjrfxeC8f0GTIfWBd
# c5OOCYyg/92Mvkr6dD42o42lUQkksaLR1A+R+ININRrdnIMr/RGey+M9Sh1izbiQ
# rEJ0Q42VFuOngUKU2Xws5ONQmhxmGkwQSJ/e5U6g93BjiSjkoGOZTjvQjFwW9zYo
# AJ8kYmmH4aOWKp5MNibZtfO4ngT9+lMKEF5G2jPOhixEVHwUGDuOlbLH2cYRdtyn
# ldWn4KVSe4MS2HOtaC/YhJrWSR1SbhNtkqd+fqojvQoI4EyY/GJHM8/uGmrsQfjc
# S6yuehnB9PUkEssidCie27+HABPnrL7tk4D2EiA0anPtims0SrE1IoPcHPj7AJyN
# BpMLCFM2kK1xL3WaR8p4N6nSg6LiyTGQLxYNWqaoA8fIF1K1n7Ut04k8WigOJcl7
# bB4YTD2rtE9bF2WsasPnJ/kUXcNaSRMI2pEh6HzjPeHOa8RwsnPLzdE19rMZd4Ze
# JnXzVR1nun/zhtcSKCVnXPIIXHh0arEPw6TOtF6peNK65fJk0LdQQ629EQE08+dv
# FvEerL0DHF0cUx1tYSeLEOmDB6Sxqc6ygoeF6NWmDLnXFFff3ipLUMJMFZ8=
# SIG # End Windows Authenticode signature block
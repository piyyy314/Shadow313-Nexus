"""
tests/unit/v4/test_webshell_detector.py
Tests for WebShellDetector — T1505.003 (Server Software Component: Web Shell)
"""
from __future__ import annotations

import pytest
from shadow313.v4.detection.webshell_detector import (
    WebShellDetector,
    WebShellDetectionResult,
    WebShellFinding,
    WEBSHELL_SIGNATURES,
    WEBSHELL_ACCESS_PATTERNS,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    return WebShellDetector(threshold=0.65)


# ── Signature coverage ────────────────────────────────────────────────────────

class TestSignatureCoverage:
    def test_signatures_loaded(self):
        assert len(WEBSHELL_SIGNATURES) >= 14

    def test_all_signatures_have_required_fields(self):
        for sig_id, sig in WEBSHELL_SIGNATURES.items():
            assert "technique"   in sig, f"{sig_id} missing technique"
            assert "name"        in sig, f"{sig_id} missing name"
            assert "risk"        in sig, f"{sig_id} missing risk"
            assert "patterns"    in sig, f"{sig_id} missing patterns"
            assert "description" in sig, f"{sig_id} missing description"
            assert sig["risk"] >= 0.0 and sig["risk"] <= 1.0

    def test_all_techniques_are_t1505(self):
        for sig_id, sig in WEBSHELL_SIGNATURES.items():
            assert sig["technique"].startswith("T1505"), \
                f"{sig_id} has wrong technique: {sig['technique']}"

    def test_access_patterns_loaded(self):
        assert len(WEBSHELL_ACCESS_PATTERNS) >= 5


# ── PHP Web Shell Detection ───────────────────────────────────────────────────

class TestPHPWebShells:
    def test_china_chopper_detected(self, detector):
        content = "<?php @eval($_POST['cmd']); ?>"
        result = detector.scan_content(content, file_path="shell.php")
        assert result.detected
        assert result.score >= 0.90

    def test_eval_base64_detected(self, detector):
        content = "<?php eval(base64_decode($_POST['x'])); ?>"
        result = detector.scan_content(content)
        assert result.detected
        assert result.score >= 0.85

    def test_system_get_detected(self, detector):
        content = "<?php system($_GET['cmd']); ?>"
        result = detector.scan_content(content)
        assert result.detected
        assert result.score >= 0.85

    def test_passthru_post_detected(self, detector):
        content = "<?php passthru($_POST['c']); ?>"
        result = detector.scan_content(content)
        assert result.detected

    def test_shell_exec_request_detected(self, detector):
        content = "<?php echo shell_exec($_REQUEST['cmd']); ?>"
        result = detector.scan_content(content)
        assert result.detected

    def test_preg_replace_e_detected(self, detector):
        content = "<?php preg_replace('/.*/e', $_POST['c'], ''); ?>"
        result = detector.scan_content(content)
        assert result.detected

    def test_assert_post_detected(self, detector):
        content = "<?php assert($_POST['cmd']); ?>"
        result = detector.scan_content(content)
        assert result.detected

    def test_wso_shell_detected(self, detector):
        content = "WSO 2.8 // $auth_pass = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';"
        result = detector.scan_content(content)
        assert result.detected
        assert result.score >= 0.90

    def test_eval_gzinflate_detected(self, detector):
        content = "<?php eval(gzinflate(base64_decode('encoded_payload'))); ?>"
        result = detector.scan_content(content)
        assert result.detected

    def test_proc_open_request_detected(self, detector):
        content = "<?php $h = proc_open($_REQUEST['cmd'], $desc, $pipes); ?>"
        result = detector.scan_content(content)
        assert result.detected

    def test_legitimate_php_not_flagged(self, detector):
        content = """<?php
        function greet($name) {
            return "Hello, " . htmlspecialchars($name);
        }
        echo greet($_GET['name'] ?? 'World');
        ?>"""
        result = detector.scan_content(content)
        # Should not trigger high-confidence detection
        assert result.score < 0.65

    def test_hex_obfuscation_detected(self, detector):
        content = r"<?php $x = \x73\x79\x73\x74\x65\x6d\x28\x24\x5f\x47\x45\x54\x5b\x27\x63\x27\x5d\x29; ?>"
        result = detector.scan_content(content)
        assert result.detected


# ── ASP/ASPX Web Shell Detection ─────────────────────────────────────────────

class TestASPXWebShells:
    def test_asp_eval_request_detected(self, detector):
        content = "<% eval request(\"cmd\") %>"
        result = detector.scan_content(content, file_path="shell.asp")
        assert result.detected

    def test_aspx_execute_request_detected(self, detector):
        content = "<% execute request(\"c\") %>"
        result = detector.scan_content(content)
        assert result.detected

    def test_aspx_process_start_detected(self, detector):
        content = 'System.Diagnostics.Process.Start("cmd.exe", "/c " + Request["cmd"]);'
        result = detector.scan_content(content)
        assert result.detected

    def test_cmd_exe_request_detected(self, detector):
        content = 'cmd.exe /c ' + 'Request["command"]'
        result = detector.scan_content(content)
        assert result.detected


# ── JSP Web Shell Detection ───────────────────────────────────────────────────

class TestJSPWebShells:
    def test_runtime_exec_detected(self, detector):
        content = 'Runtime.getRuntime().exec(request.getParameter("cmd"));'
        result = detector.scan_content(content, file_path="shell.jsp")
        assert result.detected
        assert result.score >= 0.85

    def test_process_builder_detected(self, detector):
        content = 'new ProcessBuilder(request.getParameter("cmd")).start();'
        result = detector.scan_content(content)
        assert result.detected

    def test_classloader_defineclass_detected(self, detector):
        content = 'URLClassLoader cl = new URLClassLoader(); cl.defineClass(Base64.decode(request.getParameter("c")));'
        result = detector.scan_content(content)
        assert result.detected


# ── Python/Perl CGI Shell Detection ──────────────────────────────────────────

class TestCGIShells:
    def test_python_cgi_os_system_detected(self, detector):
        content = """import cgi
form = cgi.FieldStorage()
os.system(form.getvalue('cmd'))"""
        result = detector.scan_content(content, file_path="shell.py")
        assert result.detected

    def test_python_exec_base64_detected(self, detector):
        content = "exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk='))"
        result = detector.scan_content(content)
        assert result.detected

    def test_perl_cgi_system_detected(self, detector):
        content = """use CGI;
my $q = new CGI;
system($q->param('cmd'));"""
        result = detector.scan_content(content, file_path="shell.pl")
        assert result.detected


# ── Upload Path Detection ─────────────────────────────────────────────────────

class TestUploadPathDetection:
    def test_php_in_uploads_detected(self, detector):
        content = "<?php echo 'ok'; ?>"
        result = detector.scan_content(content, file_path="uploads/image.php")
        # File path itself should trigger
        result2 = detector.scan_content("uploads/image.php")
        assert result2.detected or result.score > 0.0

    def test_php_in_wp_content_detected(self, detector):
        content = "wp-content/uploads/2024/shell.php"
        result = detector.scan_content(content)
        assert result.detected

    def test_shell_named_file_detected(self, detector):
        content = "/var/www/html/shell.php"
        result = detector.scan_content(content)
        assert result.detected


# ── Access Log Detection ──────────────────────────────────────────────────────

class TestAccessLogDetection:
    def test_shell_command_in_url_detected(self, detector):
        log = '192.168.1.1 - - [01/Jan/2026] "GET /page.php?cmd=whoami HTTP/1.1" 200 512'
        result = detector.scan_access_log(log)
        assert result.detected
        assert result.score >= 0.85

    def test_post_to_image_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "POST /uploads/photo.jpg HTTP/1.1" 200 1024'
        result = detector.scan_access_log(log)
        assert result.detected

    def test_antsword_useragent_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "POST /shell.php HTTP/1.1" 200 512 "antSword/2.1"'
        result = detector.scan_access_log(log)
        assert result.detected
        assert result.score >= 0.95

    def test_base64_cmd_in_url_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "GET /page.php?cmd=aWQgJiYgd2hvYW1p HTTP/1.1" 200 256'
        result = detector.scan_access_log(log)
        assert result.detected

    def test_godzilla_useragent_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "POST /upload/img.php HTTP/1.1" 200 2048 "Godzilla/4.0"'
        result = detector.scan_access_log(log)
        assert result.detected
        assert result.score >= 0.95

    def test_clean_log_not_flagged(self, detector):
        log = '192.168.1.100 - - [01/Jan/2026] "GET /index.html HTTP/1.1" 200 4096 "Mozilla/5.0"'
        result = detector.scan_access_log(log)
        assert not result.detected


# ── score_event() pipeline interface ─────────────────────────────────────────

class TestScoreEvent:
    def test_china_chopper_event_scored(self, detector):
        event = {
            "event_type": "http_request",
            "content": "<?php @eval($_POST['cmd']); ?>",
            "file_path": "uploads/image.php",
        }
        score = detector.score_event(event)
        assert score >= 0.65

    def test_file_create_in_webroot_scored(self, detector):
        event = {
            "event_type": "file_create",
            "file_path": "/var/www/html/uploads/shell.php",
        }
        score = detector.score_event(event)
        assert score >= 0.80

    def test_post_to_image_scored(self, detector):
        event = {
            "event_type": "http_request",
            "http_method": "POST",
            "file_path": "/uploads/photo.jpg",
        }
        score = detector.score_event(event)
        assert score >= 0.70

    def test_antsword_ua_scored(self, detector):
        event = {
            "event_type": "http_request",
            "http_method": "POST",
            "file_path": "/shell.php",
            "user_agent": "antSword/2.1",
        }
        score = detector.score_event(event)
        assert score >= 0.90

    def test_clean_event_low_score(self, detector):
        event = {
            "event_type": "http_request",
            "http_method": "GET",
            "file_path": "/index.html",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        }
        score = detector.score_event(event)
        assert score < 0.65

    def test_runtime_exec_event_scored(self, detector):
        event = {
            "event_type": "http_request",
            "content": 'Runtime.getRuntime().exec(request.getParameter("cmd"));',
            "file_path": "webapps/ROOT/shell.jsp",
        }
        score = detector.score_event(event)
        assert score >= 0.65

    def test_empty_event_zero_score(self, detector):
        score = detector.score_event({})
        assert score == 0.0


# ── Result data structures ────────────────────────────────────────────────────

class TestResultStructures:
    def test_finding_to_dict(self, detector):
        content = "<?php @eval($_POST['cmd']); ?>"
        result = detector.scan_content(content, file_path="shell.php")
        assert result.detected
        d = result.findings[0].to_dict()
        assert "signature_id"    in d
        assert "signature_name"  in d
        assert "technique"       in d
        assert "risk_score"      in d
        assert "matched_text"    in d
        assert "description"     in d
        assert "timestamp"       in d

    def test_result_to_dict(self, detector):
        content = "<?php system($_GET['cmd']); ?>"
        result = detector.scan_content(content)
        d = result.to_dict()
        assert d["detected"]       is True
        assert d["technique"]      == "T1505.003"
        assert d["finding_count"]  >= 1
        assert "findings"          in d
        assert "timestamp"         in d

    def test_no_findings_result(self, detector):
        content = "<?php echo 'Hello World'; ?>"
        result = detector.scan_content(content)
        d = result.to_dict()
        assert d["finding_count"] == 0
        assert d["detected"] is False

    def test_lines_scanned_counted(self, detector):
        content = "line1\nline2\nline3\n<?php system($_GET['cmd']); ?>"
        result = detector.scan_content(content)
        assert result.lines_scanned == 4

    def test_matched_text_truncated(self, detector):
        long_content = "<?php @eval($_POST['cmd']); ?>" + "A" * 500
        result = detector.scan_content(long_content)
        if result.findings:
            d = result.findings[0].to_dict()
            assert len(d["matched_text"]) <= 200


# ── Score aggregation ─────────────────────────────────────────────────────────

class TestScoreAggregation:
    def test_multiple_findings_increase_score(self, detector):
        # Multiple shell patterns in one file
        content = """<?php
@eval($_POST['cmd']);
system($_GET['c']);
passthru($_REQUEST['x']);
"""
        result = detector.scan_content(content)
        assert result.score >= 0.95

    def test_score_capped_at_1(self, detector):
        content = """<?php
@eval($_POST['cmd']);
system($_GET['c']);
passthru($_REQUEST['x']);
assert($_POST['a']);
shell_exec($_COOKIE['s']);
"""
        result = detector.scan_content(content)
        assert result.score <= 1.0

    def test_high_risk_sig_dominates(self, detector):
        # China Chopper (0.99) should dominate score
        content = "<?php @eval($_POST['cmd']); ?>"
        result = detector.scan_content(content)
        assert result.score >= 0.90


# ── Threshold behaviour ───────────────────────────────────────────────────────

class TestThreshold:
    def test_custom_threshold_respected(self):
        detector_strict = WebShellDetector(threshold=0.99)
        content = "<?php system($_GET['cmd']); ?>"
        result = detector_strict.scan_content(content)
        # Score is high but may not reach 0.99 for single pattern
        assert result.score >= 0.85  # score still computed correctly

    def test_default_threshold_is_065(self):
        d = WebShellDetector()
        assert d.threshold == 0.65

    def test_low_threshold_detects_more(self):
        detector_loose = WebShellDetector(threshold=0.30)
        content = "uploads/image.php"
        result = detector_loose.scan_content(content)
        assert result.detected


# ── ATT&CK technique mapping ──────────────────────────────────────────────────

class TestATTACKMapping:
    def test_technique_id_in_result(self, detector):
        content = "<?php @eval($_POST['cmd']); ?>"
        result = detector.scan_content(content)
        assert result.technique == "T1505.003"

    def test_technique_name_in_result(self, detector):
        content = "<?php @eval($_POST['cmd']); ?>"
        result = detector.scan_content(content)
        assert "Web Shell" in result.technique_name

    def test_finding_technique_matches(self, detector):
        content = "<?php @eval($_POST['cmd']); ?>"
        result = detector.scan_content(content)
        for finding in result.findings:
            assert finding.technique.startswith("T1505")


# ── Extended Signature Tests (v4.1 Gap Closure) ───────────────────────────────

class TestPHPExtendedShells:
    def test_create_function_detected(self, detector):
        content = "$f = create_function('', $_POST['cmd']); $f();"
        result = detector.scan_content(content)
        assert result.detected

    def test_variable_function_detected(self, detector):
        content = "$x = 'system'; $x($_GET['cmd']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_call_user_func_detected(self, detector):
        content = "call_user_func($_GET['func'], $_GET['arg']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_array_map_shell_detected(self, detector):
        content = "array_map('system', $_GET['cmds']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_array_filter_shell_detected(self, detector):
        content = "array_filter($_GET['c'], 'exec');"
        result = detector.scan_content(content)
        assert result.detected

    def test_mail_shell_detected(self, detector):
        content = "mail('a@b.com','s','b','','-X /var/www/html/shell.php');"
        result = detector.scan_content(content)
        assert result.detected

    def test_reflection_function_detected(self, detector):
        content = "$r = new ReflectionFunction($_GET['func']); $r->invoke();"
        result = detector.scan_content(content)
        assert result.detected

    def test_string_concat_obfuscation_detected(self, detector):
        content = "$f = 'sy'.'st'.'em'; $f($_GET['c']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_variable_variable_detected(self, detector):
        content = "$$a = 'system'; $$a($_GET['cmd']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_memory_shell_shutdown_detected(self, detector):
        content = "register_shutdown_function('system', $_GET['cmd']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_chr_concat_obfuscation_detected(self, detector):
        content = "$f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);"
        result = detector.scan_content(content)
        assert result.detected


class TestJSPExtendedShells:
    def test_scriptengine_detected(self, detector):
        content = 'new ScriptEngineManager().getEngineByName("js").eval(request.getParameter("cmd"));'
        result = detector.scan_content(content)
        assert result.detected

    def test_memshell_addservlet_detected(self, detector):
        content = 'StandardContext ctx = (StandardContext)request.getServletContext(); ctx.addServletMappingDecoded("/shell", "ShellServlet");'
        result = detector.scan_content(content)
        assert result.detected

    def test_spring_spel_detected(self, detector):
        content = 'SpelExpressionParser parser = new SpelExpressionParser(); parser.parseExpression(request.getParameter("cmd")).exec();'
        result = detector.scan_content(content)
        assert result.detected

    def test_godzilla_detected(self, detector):
        content = "@ini_set('error_reporting', 0); @eval($_POST['payload']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_behinder_aes_detected(self, detector):
        content = 'new javax.crypto.spec.SecretKeySpec("key".getBytes(), "AES"); Cipher.getInstance("AES").doFinal(Base64.decode(request.getSession().getAttribute("u")));'
        result = detector.scan_content(content)
        assert result.detected

    def test_shiro_rememberme_detected(self, detector):
        content = "rememberMe=aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5nIHNoaXJvIGRlc2VyaWFsaXphdGlvbg=="
        result = detector.scan_content(content)
        assert result.detected

    def test_tomcat_filter_detected(self, detector):
        content = "StandardContext ctx = ...; FilterDef def = new FilterDef(); def.setFilterClass(ShellFilter.class.getName()); ctx.addFilterDef(def);"
        result = detector.scan_content(content)
        assert result.detected

    def test_aspx_memory_shell_detected(self, detector):
        content = "Assembly.Load(Convert.FromBase64String(Request[\"d\"])).GetType(\"Shell\").GetMethod(\"Run\").Invoke(null, new object[]{Request[\"c\"]});"
        result = detector.scan_content(content)
        assert result.detected


class TestNodeJSShells:
    def test_child_process_exec_detected(self, detector):
        content = "const {exec} = require('child_process'); exec(req.body.cmd, (e,o)=>res.send(o));"
        result = detector.scan_content(content)
        assert result.detected

    def test_child_process_execsync_detected(self, detector):
        content = "require('child_process').execSync(req.query.cmd)"
        result = detector.scan_content(content)
        assert result.detected

    def test_nodejs_eval_req_detected(self, detector):
        content = "app.post('/shell', (req,res) => { eval(req.body.code); });"
        result = detector.scan_content(content)
        assert result.detected

    def test_nodejs_new_function_detected(self, detector):
        content = "const fn = new Function(req.body.code); fn();"
        result = detector.scan_content(content)
        assert result.detected

    def test_nodejs_vm_detected(self, detector):
        content = "const vm = require('vm'); vm.runInNewContext(req.query.code);"
        result = detector.scan_content(content)
        assert result.detected

    def test_clean_nodejs_not_flagged(self, detector):
        content = "const express = require('express'); app.get('/', (req,res) => res.send('Hello'));"
        result = detector.scan_content(content)
        assert result.score < 0.65


class TestRubyShells:
    def test_ruby_system_params_detected(self, detector):
        content = "system(params[:cmd])"
        result = detector.scan_content(content, file_path="shell.rb")
        assert result.detected

    def test_ruby_backtick_interpolation_detected(self, detector):
        content = 'output = `#{params[:cmd]}`'
        result = detector.scan_content(content)
        assert result.detected

    def test_ruby_eval_params_detected(self, detector):
        content = "eval(params[:code])"
        result = detector.scan_content(content)
        assert result.detected

    def test_ruby_instance_eval_detected(self, detector):
        content = "instance_eval(request.body.read)"
        result = detector.scan_content(content)
        assert result.detected

    def test_ruby_io_popen_detected(self, detector):
        content = "IO.popen(params[:cmd]) {|f| f.read}"
        result = detector.scan_content(content)
        assert result.detected


class TestColdFusionShells:
    def test_cfexecute_cmd_detected(self, detector):
        content = '<cfexecute name="cmd.exe" arguments="/c #URL.cmd#" variable="output" />'
        result = detector.scan_content(content, file_path="shell.cfm")
        assert result.detected

    def test_cfexecute_bash_detected(self, detector):
        content = '<cfexecute name="/bin/bash" arguments="-c #FORM.cmd#" />'
        result = detector.scan_content(content)
        assert result.detected

    def test_coldfusion_evaluate_url_detected(self, detector):
        content = "<cfset result = evaluate(URL.expr)>"
        result = detector.scan_content(content)
        assert result.detected


class TestUnicodeObfuscation:
    def test_unicode_system_detected(self, detector):
        content = r"$f = '\u0073\u0079\u0073\u0074\u0065\u006d'; $f($_GET['c']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_unicode_eval_detected(self, detector):
        content = r"\u0065\u0076\u0061\u006c($_POST['x']);"
        result = detector.scan_content(content)
        assert result.detected

    def test_hex_escape_system_detected(self, detector):
        content = r"$f = '\x73\x79\x73\x74\x65\x6d'; $f($_GET['c']);"
        result = detector.scan_content(content)
        assert result.detected


class TestExtendedAccessLogPatterns:
    def test_double_extension_upload_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "POST /uploads/photo.jpg.php HTTP/1.1" 200 512'
        result = detector.scan_access_log(log)
        assert result.detected
        assert result.score >= 0.80

    def test_unusual_verb_to_script_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "TRACK /admin/shell.php HTTP/1.1" 200 256'
        result = detector.scan_access_log(log)
        assert result.detected

    def test_scanner_ua_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "GET /admin/ HTTP/1.1" 200 1024 "sqlmap/1.7"'
        result = detector.scan_access_log(log)
        assert result.detected

    def test_trace_to_script_detected(self, detector):
        log = '10.0.0.1 - - [01/Jan/2026] "TRACE /index.asp HTTP/1.1" 200 128'
        result = detector.scan_access_log(log)
        assert result.detected


class TestExtendedCoverage:
    def test_total_signatures_count(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        assert len(WEBSHELL_SIGNATURES) >= 35

    def test_total_access_patterns_count(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_ACCESS_PATTERNS
        assert len(WEBSHELL_ACCESS_PATTERNS) >= 9

    def test_nodejs_signatures_present(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        assert "nodejs_child_process" in WEBSHELL_SIGNATURES
        assert "nodejs_eval_shell"    in WEBSHELL_SIGNATURES

    def test_ruby_signatures_present(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        assert "ruby_cgi_shell"  in WEBSHELL_SIGNATURES
        assert "ruby_eval_shell" in WEBSHELL_SIGNATURES

    def test_coldfusion_signatures_present(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        assert "coldfusion_cfexecute" in WEBSHELL_SIGNATURES
        assert "coldfusion_evaluate"  in WEBSHELL_SIGNATURES

    def test_memory_shell_signatures_present(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        assert "php_memory_shell"  in WEBSHELL_SIGNATURES
        assert "jsp_memshell"      in WEBSHELL_SIGNATURES
        assert "aspx_memory_shell" in WEBSHELL_SIGNATURES

    def test_behinder_godzilla_present(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        assert "behinder_shell" in WEBSHELL_SIGNATURES
        assert "godzilla_shell" in WEBSHELL_SIGNATURES

    def test_all_extended_sigs_have_required_fields(self):
        from shadow313.v4.detection.webshell_detector import WEBSHELL_SIGNATURES
        for sig_id, sig in WEBSHELL_SIGNATURES.items():
            assert "technique"   in sig, f"{sig_id} missing technique"
            assert "name"        in sig, f"{sig_id} missing name"
            assert "risk"        in sig, f"{sig_id} missing risk"
            assert "patterns"    in sig, f"{sig_id} missing patterns"
            assert "description" in sig, f"{sig_id} missing description"
            assert 0.0 <= sig["risk"] <= 1.0, f"{sig_id} risk out of range"

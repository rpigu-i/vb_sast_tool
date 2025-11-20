"""
Test suite for VB SAST Tool Rules
----------------------------------
Tests each pattern in the rules YAML file against example VB code
to ensure proper detection of vulnerabilities.
"""
import re
import sys
import pytest
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from vb_sast_tool.scan_vb_vulnerabilities import load_rules, scan_file


@pytest.fixture
def rules():
    """Load the rules from the YAML file"""
    rules_path = Path(__file__).parent.parent / "rules" / "rules.yaml"
    return load_rules(str(rules_path))


@pytest.fixture
def rule_by_id(rules):
    """Create a dictionary mapping rule IDs to rule objects"""
    return {rule['id']: rule for rule in rules}


class TestHardcodedPassword:
    """Tests for VB_HARDCODED_PASSWORD rule"""
    
    def test_hardcoded_password_with_equals(self, rule_by_id):
        """Test detection of hardcoded password with = assignment"""
        code = 'password = "SuperSecret123!"'
        rule = rule_by_id['VB_HARDCODED_PASSWORD']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect hardcoded password with ="
        
    def test_hardcoded_password_with_colon(self, rule_by_id):
        """Test detection of hardcoded password with : assignment"""
        code = 'password: "MyPassword"'
        rule = rule_by_id['VB_HARDCODED_PASSWORD']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect hardcoded password with :"
        
    def test_hardcoded_password_single_quotes(self, rule_by_id):
        """Test detection of hardcoded password with single quotes"""
        code = "password = 'secret123'"
        rule = rule_by_id['VB_HARDCODED_PASSWORD']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect hardcoded password with single quotes"
    
    def test_hardcoded_password_case_insensitive(self, rule_by_id):
        """Test detection is case-insensitive"""
        code = 'Password = "Test123"'
        rule = rule_by_id['VB_HARDCODED_PASSWORD']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect Password with capital P"


class TestEvalUsage:
    """Tests for VB_EVAL_USAGE rule"""
    
    def test_eval_function_call(self, rule_by_id):
        """Test detection of Eval function call"""
        code = 'x = Eval("2+2")'
        rule = rule_by_id['VB_EVAL_USAGE']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect Eval() usage"
    
    def test_eval_with_spaces(self, rule_by_id):
        """Test detection of Eval with spaces"""
        code = 'result = Eval  ("expression")'
        rule = rule_by_id['VB_EVAL_USAGE']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect Eval with spaces before ("
        
    def test_eval_case_insensitive(self, rule_by_id):
        """Test detection is case-insensitive"""
        code = 'x = eval("test")'
        rule = rule_by_id['VB_EVAL_USAGE']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect eval in lowercase"


class TestSQLConcatenation:
    """Tests for VB_SQL_CONCAT rule"""
    
    def test_select_concatenation(self, rule_by_id):
        """Test detection of SQL SELECT with string concatenation"""
        code = 'sql = "SELECT * FROM Users" & username'
        rule = rule_by_id['VB_SQL_CONCAT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect SELECT with concatenation"
    
    def test_select_concatenation_complex(self, rule_by_id):
        """Test detection of complex SQL concatenation"""
        code = '''sql = "SELECT * FROM Users WHERE Username = '" & username & "'"'''
        rule = rule_by_id['VB_SQL_CONCAT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect SELECT with embedded concatenation"
    
    def test_executesql_concatenation(self, rule_by_id):
        """Test detection of ExecuteSql with concatenation"""
        code = 'Call ExecuteSql(query & userInput)'
        rule = rule_by_id['VB_SQL_CONCAT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect ExecuteSql with concatenation"


class TestShellExecution:
    """Tests for VB_SHELL_EXEC rule"""
    
    def test_shell_command(self, rule_by_id):
        """Test detection of Shell command"""
        code = 'Shell "cmd.exe /c dir", vbHide'
        rule = rule_by_id['VB_SHELL_EXEC']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect Shell command"
    
    def test_wscript_shell_double_quotes(self, rule_by_id):
        """Test detection of WScript.Shell with double quotes"""
        code = 'Set objShell = CreateObject("WScript.Shell")'
        rule = rule_by_id['VB_SHELL_EXEC']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect WScript.Shell with double quotes"
    
    def test_wscript_shell_single_quotes(self, rule_by_id):
        """Test detection of WScript.Shell with single quotes"""
        code = "Set objShell = CreateObject('WScript.Shell')"
        rule = rule_by_id['VB_SHELL_EXEC']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect WScript.Shell with single quotes"


class TestFileSystemAccess:
    """Tests for VB_FILESYSTEM rule"""
    
    def test_filesystemobject(self, rule_by_id):
        """Test detection of FileSystemObject"""
        code = 'Set fs = CreateObject("Scripting.FileSystemObject")'
        rule = rule_by_id['VB_FILESYSTEM']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect FileSystemObject"
    
    def test_open_statement_double_quotes(self, rule_by_id):
        """Test detection of Open statement with double quotes"""
        code = 'Open "C:\\data\\file.txt" For Input As #1'
        rule = rule_by_id['VB_FILESYSTEM']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect Open statement with double quotes"
    
    def test_open_statement_single_quotes(self, rule_by_id):
        """Test detection of Open statement with single quotes"""
        code = "Open 'C:\\users\\data.txt' For Output As #2"
        rule = rule_by_id['VB_FILESYSTEM']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect Open statement with single quotes"


class TestHTTPURL:
    """Tests for VB_HTTP_URL rule"""
    
    def test_http_url_basic(self, rule_by_id):
        """Test detection of basic HTTP URL"""
        code = 'url = "http://example.com/api"'
        rule = rule_by_id['VB_HTTP_URL']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect HTTP URL"
    
    def test_http_url_with_path(self, rule_by_id):
        """Test detection of HTTP URL with path"""
        code = 'url = "http://insecure.example.com/api/endpoint"'
        rule = rule_by_id['VB_HTTP_URL']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect HTTP URL with path"
    
    def test_http_url_with_query(self, rule_by_id):
        """Test detection of HTTP URL with query parameters"""
        code = 'url = "http://example.com/api?param=value"'
        rule = rule_by_id['VB_HTTP_URL']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect HTTP URL with query string"
    
    def test_https_not_detected(self, rule_by_id):
        """Test that HTTPS URLs are not detected (only HTTP)"""
        code = 'url = "https://secure.example.com/api"'
        rule = rule_by_id['VB_HTTP_URL']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) == 0, "Should NOT detect HTTPS URL"


class TestGotoStatement:
    """Tests for VB_GOTO_STATEMENT rule"""
    
    def test_goto_statement(self, rule_by_id):
        """Test detection of GoTo statement"""
        code = 'GoTo ErrorHandler'
        rule = rule_by_id['VB_GOTO_STATEMENT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect GoTo statement"
    
    def test_goto_case_insensitive(self, rule_by_id):
        """Test detection is case-insensitive"""
        code = 'goto NextLine'
        rule = rule_by_id['VB_GOTO_STATEMENT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect goto in lowercase"
    
    def test_goto_with_label(self, rule_by_id):
        """Test detection of GoTo with various labels"""
        code = '''
Line1:
    x = 1
    GoTo Line2
Line2:
    y = 2
'''
        rule = rule_by_id['VB_GOTO_STATEMENT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect GoTo with labels"

class TestGosubStatement:
    """Tests for VB_GOTO_STATEMENT rule"""
    
    def test_gosub_statement(self, rule_by_id):
        """Test detection of GoSub statement"""
        code = 'GoSub ErrorHandler'
        rule = rule_by_id['VB_GOSUB_STATEMENT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect GoSub statement"
    
    def test_gosub_case_insensitive(self, rule_by_id):
        """Test detection is case-insensitive"""
        code = 'gosub NextLine'
        rule = rule_by_id['VB_GOSUB_STATEMENT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect gosub in lowercase"
    
    def test_gosub_with_label(self, rule_by_id):
        """Test detection of GoSub with various labels"""
        code = '''
Sub BadProcedure()
    GoSub BadSubRoutine
    Exit Sub
BadSubRoutine:
    y = 2
    Return
End Sub
'''
        rule = rule_by_id['VB_GOSUB_STATEMENT']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect GoSub with labels"


class TestHardcodedIP:
    """Tests for VB_HARDCODED_IP rule"""
    
    def test_hardcoded_ip_double_quotes(self, rule_by_id):
        """Test detection of hardcoded IP address with double quotes"""
        code = 'sockMain.RemoteHost = "192.168.11.11"'
        rule = rule_by_id['VB_HARDCODED_IP']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect hardcoded IP with double quotes"
    
    def test_hardcoded_ip_single_quotes(self, rule_by_id):
        """Test detection of hardcoded IP address with single quotes"""
        code = "serverIP = '10.0.0.1'"
        rule = rule_by_id['VB_HARDCODED_IP']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) > 0, "Should detect hardcoded IP with single quotes"
    
    def test_hardcoded_ip_various_ranges(self, rule_by_id):
        """Test detection of IP addresses in various ranges"""
        test_cases = [
            'ip = "192.168.1.1"',
            'address = "10.20.30.40"',
            'host = "172.16.0.1"',
            'server = "8.8.8.8"',
        ]
        rule = rule_by_id['VB_HARDCODED_IP']
        for code in test_cases:
            matches = list(rule['regex'].finditer(code))
            assert len(matches) > 0, f"Should detect IP in: {code}"
    
    def test_hardcoded_ip_not_detected_without_quotes(self, rule_by_id):
        """Test that IP addresses without quotes are not detected"""
        code = 'comment about 192.168.1.1 without quotes'
        rule = rule_by_id['VB_HARDCODED_IP']
        matches = list(rule['regex'].finditer(code))
        assert len(matches) == 0, "Should NOT detect IP without quotes"

class TestExampleFiles:
    """Integration tests using the example VB files"""
    
    def test_module1_has_findings(self, rules):
        """Test that module1.bas produces findings"""
        module1_path = Path(__file__).parent.parent / "examples" / "vb_exports" / "module1.bas"
        findings = scan_file(str(module1_path), rules)
        
        # Should have findings
        assert len(findings) > 0, "module1.bas should have vulnerability findings"
        
        # Check for specific expected findings based on the rules
        rule_ids = {f['rule_id'] for f in findings}
        
        # SQL concatenation should be found
        assert 'VB_SQL_CONCAT' in rule_ids, "Should find SQL concatenation vulnerability"
    
    def test_form_login_has_findings(self, rules):
        """Test that form_login.frm produces findings"""
        form_path = Path(__file__).parent.parent / "examples" / "vb_exports" / "form_login.frm"
        findings = scan_file(str(form_path), rules)
        
        # Should have findings
        assert len(findings) > 0, "form_login.frm should have vulnerability findings"
        
        # Check for SQL concatenation (known to be in the file)
        rule_ids = {f['rule_id'] for f in findings}
        assert 'VB_SQL_CONCAT' in rule_ids, "Should find SQL concatenation in form_login.frm"


class TestAllRulesPresent:
    """Test that all expected rules are loaded"""
    
    def test_all_rules_loaded(self, rules):
        """Verify all 9 rules are loaded from the YAML file"""
        assert len(rules) == 9, "Should load exactly 9 rules from rules.yaml"
    
    def test_required_rule_ids_present(self, rule_by_id):
        """Verify all expected rule IDs are present"""
        expected_ids = [
            'VB_HARDCODED_PASSWORD',
            'VB_EVAL_USAGE',
            'VB_SQL_CONCAT',
            'VB_SHELL_EXEC',
            'VB_FILESYSTEM',
            'VB_HTTP_URL',
            'VB_GOTO_STATEMENT',
            'VB_GOSUB_STATEMENT',
            'VB_HARDCODED_IP'
        ]
        
        for rule_id in expected_ids:
            assert rule_id in rule_by_id, f"Rule {rule_id} should be present in rules.yaml"
    
    def test_all_rules_have_compiled_regex(self, rules):
        """Verify all rules have compiled regex patterns"""
        for rule in rules:
            assert 'regex' in rule, f"Rule {rule['id']} should have compiled regex"
            assert rule['regex'] is not None, f"Rule {rule['id']} regex should not be None"

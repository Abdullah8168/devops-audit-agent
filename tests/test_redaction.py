from auditor.redaction import find_secrets, is_placeholder, redact

AWS = "AKIA" + "Q3EGRTZXMPLW7Y2B"  # built at runtime so the test file itself holds no literal key


def test_provider_tokens_are_masked():
    text = f'aws_key = "{AWS}"\ntoken = "ghp_' + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + '"'
    out = redact(text)
    assert AWS not in out
    assert "ghp_a1B2" not in out
    assert "[REDACTED:aws_access_key_id]" in out
    assert out.count("\n") == text.count("\n")


def test_generic_assignment_masks_value_but_keeps_name():
    out = redact('DB_PASSWORD = "S3cr3t-Pa55w0rd!"')
    assert "S3cr3t" not in out
    assert out.startswith("DB_PASSWORD = ")
    assert "[REDACTED:len=16]" in out


def test_dotenv_style_unquoted_value_is_masked():
    out = redact("export API_KEY=abcd1234efgh5678\nDEBUG=true")
    assert "abcd1234" not in out
    assert "DEBUG=true" in out


def test_references_and_placeholders_are_left_alone():
    samples = [
        "password: ${{ secrets.DB_PASSWORD }}",
        'api_key = os.environ["API_KEY"]',
        'token = os.getenv("TOKEN")',
        "API_KEY=your-api-key-here",
        "SECRET_KEY=changeme",
    ]
    for s in samples:
        assert redact(s) == s, s
        assert find_secrets(s) == [], s


def test_private_key_block_body_is_masked_line_by_line():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----"
    out = redact(text)
    assert "MIIEow" not in out
    assert out.count("\n") == 3
    hits = find_secrets(text)
    assert len(hits) == 1 and hits[0].kind == "private_key" and hits[0].line == 1


def test_url_credentials_are_masked():
    out = redact("DATABASE_URL = postgres://admin:hunter2pass@db.internal:5432/app")
    assert "hunter2pass" not in out


def test_find_secrets_reports_line_and_kind_without_value():
    hits = find_secrets(f"x = 1\nKEY = '{AWS}'\n")
    assert len(hits) == 1
    assert hits[0].line == 2 and hits[0].kind == "aws_access_key_id"
    assert AWS not in hits[0].masked_line


def test_placeholder_detection():
    assert is_placeholder("${API_KEY}")
    assert is_placeholder("<your token>")
    assert is_placeholder("3600")
    assert not is_placeholder("k8Fh2LpQ9zX")


def test_documented_example_keys_are_labelled_not_masked():
    line = 'EXAMPLE = "AKIAIOSFODNN7EXAMPLE"'
    assert redact(line) == line
    hits = find_secrets(line)
    assert hits and "documented example" in hits[0].kind

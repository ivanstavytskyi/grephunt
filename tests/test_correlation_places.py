"""One problem, one finding: correlation by vulnerability class, place, and text similarity."""
from __future__ import annotations

from grephunt.finding_model.clustering import cluster_by_text, cosine, tfidf_vectors
from grephunt.finding_model.correlation import correlate
from grephunt.finding_model.record import Category, Finding, Location, Module, Severity
from grephunt.finding_model.vuln_class import clean_path, iac_topic, vulnerability_class


def _code(tool: str, rule: str, path: str, line: int | None, cwe: list[str] | None = None, title: str = "", severity=Severity.HIGH) -> Finding:
    return Finding(tool=tool, rule_id=rule, title=title or rule, severity=severity, cwe=cwe or [],
                   location=Location(path=path, start_line=line, end_line=line))


def _iac(tool: str, rule: str, path: str, line: int | None, title: str) -> Finding:
    return Finding(module=Module.SAST, category=Category.MISCONFIG, tool=tool, rule_id=rule, title=title, severity=Severity.MEDIUM,
                   location=Location(path=path, start_line=line, end_line=line))


def test_sql_injection_reported_by_five_tools_is_one_finding():
    reports = [
        _code("semgrep", "grephunt.php.sql-injection", "/src/users.php", 42, ["CWE-89"]),
        _code("bearer", "php_lang_sql_injection", "users.php", 42, ["CWE-89"], severity=Severity.CRITICAL),
        _code("snyk-code", "php/Sqli", "./users.php", 41, ["CWE-89"]),
        _code("devskim", "DS104456", "users.php", 42, title="Possible SQL injection"),
        _code("semgrep", "php.lang.security.tainted-sql", "users.php", 40, ["CWE-564"]),  # the input line
    ]
    merged = correlate(reports, anchors={"users.php": {42}})
    assert len(merged) == 1
    finding = merged[0]
    assert finding.location.start_line == 42
    assert finding.severity is Severity.CRITICAL
    assert len(finding.confirmations) == 5
    assert set(finding.tools) == {"semgrep", "bearer", "snyk-code", "devskim"}
    assert finding.evidence.startswith("Reported by 4 tools")


def test_different_problems_on_one_line_and_far_apart_stay_apart():
    reports = [
        _code("semgrep", "sqli", "app.py", 10, ["CWE-89"]),
        _code("semgrep", "xss", "app.py", 10, ["CWE-79"]),
        _code("bandit", "B608", "app.py", 60, ["CWE-89"]),
    ]
    assert len(correlate(reports)) == 3


def test_one_rule_on_two_close_lines_is_one_finding_with_both_lines():
    reports = [
        _code("semgrep", "sqli", "medium.php", 10, ["CWE-89"]),
        _code("semgrep", "sqli", "medium.php", 12, ["CWE-89"]),
        _code("bearer", "sql", "medium.php", 12, ["CWE-89"]),
    ]
    merged = correlate(reports)
    assert len(merged) == 1
    assert merged[0].lines == [10, 12] and merged[0].location.start_line == 10
    assert len(merged[0].confirmations) == 3
    assert "2 places in this file (lines 10, 12)" in merged[0].message


def test_same_check_on_three_resources_is_one_finding():
    # The screenshot case: KICS "Unrestricted Security Group Ingress" on lines 29, 13, 21.
    reports = [
        _iac("kics", "4728cd65", "../../src/terraform/modules/network/main.tf", line, "Unrestricted Security Group Ingress")
        for line in (29, 13, 21)
    ]
    merged = correlate(reports)
    assert len(merged) == 1
    assert merged[0].lines == [13, 21, 29]
    assert merged[0].location.start_line == 13


def test_different_rules_of_one_class_stay_apart():
    merged = correlate([
        _code("bandit", "B602", "app.py", 23, ["CWE-78"], title="subprocess call with shell=True"),
        _code("bandit", "B307", "app.py", 33, ["CWE-78"], title="Use of possibly insecure function eval"),
    ])
    assert len(merged) == 2


def test_command_injection_cwes_77_and_78_merge():
    merged = correlate([
        _code("semgrep", "subprocess-shell-true", "app.py", 23, ["CWE-78"]),
        _code("bandit", "B602", "app.py", 23, ["CWE-77"]),
    ])
    assert len(merged) == 1 and sorted(merged[0].cwe) == ["CWE-77", "CWE-78"]


def test_dockerfile_root_user_from_four_tools_is_one_finding():
    merged = correlate([
        _iac("kics", "fd54f200", "../../src/docker/backend/Dockerfile", 13, "Missing User Instruction"),
        _iac("trivy", "DS002", "docker/backend/Dockerfile", None, "Image user should not be 'root'"),
        _iac("checkov", "CKV_DOCKER_3", "/src/docker/backend/Dockerfile", 1, "Ensure that a user for the container has been created"),
        _iac("hadolint", "DL3002", "docker/backend/Dockerfile", 20, "Last USER should not be root"),
        _iac("checkov", "CKV_DOCKER_2", "docker/backend/Dockerfile", 1, "Ensure that HEALTHCHECK instructions have been added"),
    ])
    assert len(merged) == 2
    root = next(item for item in merged if len(item.confirmations) == 4)
    assert {item.tool for item in root.confirmations} == {"kics", "trivy", "checkov", "hadolint"}


def test_terraform_egress_and_ingress_stay_apart_and_repeats_fold():
    merged = correlate([
        _iac("trivy", "AWS-0104", "terraform/modules/network/main.tf", 36, "A security group rule should not allow unrestricted egress to any IP address."),
        _iac("kics", "66f2d8f9", "../../src/terraform/modules/network/main.tf", 33, "Security Group With Unrestricted Egress"),
        _iac("trivy", "AWS-0107", "terraform/modules/network/main.tf", 30, "An ingress security group rule allows traffic from /0."),
        _iac("trivy", "AWS-0104", "terraform/modules/network/main.tf", 120, "A security group rule should not allow unrestricted egress to any IP address."),
    ])
    assert len(merged) == 2
    egress = next(item for item in merged if item.lines)
    assert egress.lines == [33, 120]  # trivy 36 and kics 33 tie: the upper line of the resource wins
    assert {item.tool for item in egress.confirmations} == {"trivy", "kics"}


def test_unclassified_findings_cluster_by_text_similarity():
    merged = correlate([
        _code("devskim", "DS176209", "lib/util.js", 8, title="Suspicious comment: TODO remove debug backdoor"),
        _code("semgrep", "todo-backdoor", "lib/util.js", 9, title="Debug backdoor left in a TODO comment"),
        _code("semgrep", "insecure-cookie", "lib/util.js", 9, title="Cookie without the Secure flag"),
    ])
    assert len(merged) == 2


def test_vulnerability_classes_and_paths():
    assert vulnerability_class(["CWE-564"]) == "sql-injection"
    assert vulnerability_class([], "python.lang.security.audit.subprocess-shell-true", "") == "command-injection"
    assert vulnerability_class([], "B301", "Pickle and modules that wrap it can be unsafe") == "deserialization"
    assert vulnerability_class(["CWE-1004"]) == "cwe-1004"
    assert vulnerability_class([], "R1", "Something odd") is None
    assert iac_topic("DS002", "Image user should not be 'root'") == "container-root-user"
    assert clean_path("../../src/docker/Dockerfile") == "docker/Dockerfile"
    assert clean_path("/src/app.py") == clean_path("./app.py") == "app.py"


def test_tfidf_text_similarity():
    vectors = tfidf_vectors(["SQL injection in query", "Possible SQLi in raw query string", "Cookie missing Secure flag"])
    assert cosine(vectors[0], vectors[1]) > cosine(vectors[0], vectors[2])
    groups = cluster_by_text(["same text here", "same text here"], [5, 40], window=3)
    assert len(groups) == 2  # far apart lines never merge


class _MeaningModel:
    """Stand-in for the sentence-embedding model: two texts mean the same when they share a topic word."""

    TOPICS = ("monitoring", "egress", "cookie")

    def encode(self, texts):
        return [[1.0 if topic in text.lower() else 0.0 for topic in self.TOPICS] + [0.01] for text in texts]


def test_embeddings_join_findings_that_say_the_same_in_other_words(monkeypatch):
    from grephunt.finding_model import embeddings

    reports = [
        _iac("kics", "Q1", "terraform/ec2/main.tf", 10, "EC2 Instance Monitoring Disabled"),
        _iac("checkov", "CKV_AWS_126", "terraform/ec2/main.tf", 11, "Ensure that detailed monitoring is enabled for EC2 instances"),
        _iac("checkov", "CKV_AWS_135", "terraform/ec2/main.tf", 11, "Ensure that EC2 is EBS optimized"),
    ]
    monkeypatch.setattr(embeddings, "get_model", lambda: None)
    without = correlate([item.model_copy(deep=True) for item in reports])
    monkeypatch.setattr(embeddings, "get_model", lambda: _MeaningModel())
    with_model = correlate([item.model_copy(deep=True) for item in reports])
    assert len(with_model) == 2 and len(without) >= len(with_model)
    joined = next(item for item in with_model if len(item.confirmations) == 2)
    assert {item.tool for item in joined.confirmations} == {"kics", "checkov"}


def test_without_a_model_similarity_is_none(monkeypatch, tmp_path):
    from grephunt.finding_model import embeddings

    monkeypatch.setattr(embeddings, "DATA_DIR", tmp_path)
    assert embeddings.get_model() is None
    assert embeddings.similarity_matrix(["a", "b"]) is None
    monkeypatch.setenv("GREPHUNT_EMBEDDINGS", "off")
    assert not embeddings.enabled()

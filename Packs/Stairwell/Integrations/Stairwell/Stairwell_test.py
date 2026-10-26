from Stairwell import (
    Client,
    variant_discovery_command,
    file_enrichment_command,
    intake_preflight_and_upload,
    ai_triage_summarize_command,
    object_sightings_command,
    object_detonation_trigger_command,
    object_detonation_get_command,
    object_opinions_command,
    run_to_ground_generate_command,
    asn_get_whois_command,
    hostname_get_command,
    hostname_get_resolutions_command,
    hostname_batch_get_resolutions_command,
    ipaddress_get_command,
    ipaddress_lookup_cloud_provider_command,
    ipaddress_get_hostnames_resolving_to_ip_command,
    ipaddress_get_whois_command,
    utilities_get_cloud_ip_ranges_command,
    utilities_batch_canonicalize_hostnames_command,
    utilities_batch_compute_etld_plus_one_command,
    utilities_canonicalize_hostname_command,
    utilities_compute_etld_plus_one_command,
    utilities_batch_canonicalize_urls_command,
    utilities_canonicalize_url_command,
    yara_create_rule_command,
    yara_get_rule_command,
    yara_query_matches_command,
    asset_list_command,
    asset_create_command,
    asset_get_command,
    _resolve_file_source,
    _parse_int_arg,
    _hash_sha256,
    _status_code,
    test_module as run_test_module,
)
import json
import os
import tempfile
import requests
import pytest
from unittest.mock import patch, MagicMock
from CommonServerPython import CommandResults, DemistoException

API_KEY = "FAKEAPIKEY"
TEST_FILE_HASH = "e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d"
TEST_OBJECT_ID = "357d2eac00ed810e597703ef2a4dfe7c57d528944e337d7f780c2d5d3ddd6283"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


test_client = Client(api_key=API_KEY, verify=False, proxy=False)
# Aliases kept so each test reads naturally for the API surface it exercises
test_client_v1 = test_client
test_client_network = test_client
test_client_v1_base = test_client
test_intake_client = test_client


def test_variant_discovery_command_success(requests_mock):
    mock_response = util_load_json("test_data/variant_discovery_command_result.json")

    requests_mock.get("https://app.stairwell.com/v202112/variants/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results.outputs_prefix == "Stairwell.Variants"
    assert results.outputs_key_field == "sha256"
    assert results.outputs["sha256"] == TEST_FILE_HASH
    assert results.outputs["variants"] == mock_response["variants"]
    assert "File Variants Discovered" in results.readable_output


def test_variant_discovery_command_none(requests_mock):
    mock_response = util_load_json("test_data/variant_discovery_command_results_none.json")

    requests_mock.get("https://app.stairwell.com/v202112/variants/" + TEST_FILE_HASH, json=mock_response)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results.readable_output == "No variants discovered for: " + TEST_FILE_HASH
    assert results.outputs is None


def test_variant_discovery_command_notfound(requests_mock):
    mock_response = util_load_json("test_data/variant_discovery_command_results_notfound.json")

    requests_mock.get("https://app.stairwell.com/v202112/variants/" + TEST_FILE_HASH, json=mock_response, status_code=500)

    results = variant_discovery_command(test_client, TEST_FILE_HASH)
    assert results.readable_output == f"File not found or no variants available: {TEST_FILE_HASH}"


def test_file_enrichment_command(requests_mock):
    mock_response = util_load_json("test_data/file_enrichment_command_result.json")

    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, json=mock_response)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results.outputs_prefix == "Stairwell.File_Details"
    assert results.outputs_key_field == "sha256"
    assert results.outputs["sha256"] == results.outputs["summary"]["sha256"]
    assert results.outputs["raw"] == mock_response
    assert results.readable_output.startswith("# Stairwell")


def test_file_enrichment_command_notfound(requests_mock):
    mock_response = util_load_json("test_data/file_enrichment_command_result.json")

    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, json=mock_response, status_code=404)

    results = file_enrichment_command(test_client, TEST_FILE_HASH)
    assert results.readable_output == "File not found: " + TEST_FILE_HASH


# Intake Preflight and Upload Tests
def test_intake_preflight_and_upload_missing_args():
    """Test intake_preflight_and_upload with missing required arguments"""
    # Test missing asset_id
    with pytest.raises(DemistoException, match="Missing required arguments: asset_id"):
        intake_preflight_and_upload(test_intake_client, asset_id="", file_path="/path/to/file")

    # Test missing file source
    with pytest.raises(DemistoException, match="Missing file source: provide one of entry_id, url, or file_path"):
        intake_preflight_and_upload(test_intake_client, asset_id="test-asset", file_path="")


def test_intake_preflight_and_upload_already_exists():
    """Test intake_preflight_and_upload when file already exists"""
    mock_response = util_load_json("test_data/intake_preflight_already_exists.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_response

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/to/test/file.exe")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "already exists in Stairwell" in results.readable_output
    assert results.outputs.get("result") == "already_exists"
    assert "NO_ACTION_ALREADY_EXISTS" in results.readable_output


def test_intake_preflight_and_upload_success(requests_mock):
    """Test intake_preflight_and_upload with successful upload"""
    mock_preflight = util_load_json("test_data/intake_preflight_upload.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_preflight

    # Mock the upload request (upload goes through _create_session_with_retries, not the client)
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=200)

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"fake content")
        tmp_path = tmp.name

    try:
        with patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)):
            results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path=tmp_path)
    finally:
        os.unlink(tmp_path)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Upload completed successfully" in results.readable_output
    assert results.outputs.get("upload_status") == 200


def test_intake_preflight_and_upload_upload_failure(requests_mock):
    """Test intake_preflight_and_upload when upload fails"""
    mock_preflight = util_load_json("test_data/intake_preflight_upload.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_preflight

    # Mock the upload request to fail
    requests_mock.post("https://storage.googleapis.com/upload-url", status_code=500, text="Upload failed")

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"fake content")
        tmp_path = tmp.name

    try:
        with patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)):
            results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path=tmp_path)
    finally:
        os.unlink(tmp_path)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Upload failed with status 500" in results.readable_output
    assert results.outputs.get("upload_status") == 500


def test_intake_preflight_and_upload_missing_upload_info():
    """Test intake_preflight_and_upload when preflight requests upload but missing upload info"""
    mock_response = util_load_json("test_data/intake_preflight_missing_upload_info.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_response

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/to/test/file.exe")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "missing uploadUrl/fields" in results.readable_output
    assert results.outputs.get("error") == "missing_upload_instructions"


def test_intake_preflight_and_upload_unknown_action():
    """Test intake_preflight_and_upload with unknown action"""
    mock_response = util_load_json("test_data/intake_preflight_unknown_action.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_response

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/to/test/file.exe")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Unrecognized action" in results.readable_output


def test_intake_preflight_and_upload_http_error():
    """Test intake_preflight_and_upload with HTTP error"""
    mock_client = MagicMock()
    mock_client.intake_preflight.side_effect = DemistoException("500 Server Error")

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/to/test/file.exe")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "HTTP error during Intake preflight/upload" in results.readable_output
    assert "error" in results.outputs


def test_intake_preflight_and_upload_with_sha256():
    """Test intake_preflight_and_upload with provided SHA256"""
    mock_response = util_load_json("test_data/intake_preflight_already_exists.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_response

    with patch("Stairwell.os.path.exists", return_value=True):
        results = intake_preflight_and_upload(
            mock_client,
            asset_id="test-asset",
            file_path="/path/to/test/file.exe",
            sha256="e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d",
        )

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "already exists in Stairwell" in results.readable_output


def test_intake_preflight_and_upload_with_web_origin():
    """Test intake_preflight_and_upload with web origin type"""
    mock_response = util_load_json("test_data/intake_preflight_already_exists.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_response

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(
            mock_client,
            asset_id="test-asset",
            file_path="/path/to/test/file.exe",
            origin_type="web",
            origin_referrer_url="https://example.com/referrer",
            origin_host_url="https://example.com",
            origin_zone_id=123,
        )

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "already exists in Stairwell" in results.readable_output


def test_intake_preflight_and_upload_with_detonation_plan():
    """Test intake_preflight_and_upload with detonation plan"""
    mock_response = util_load_json("test_data/intake_preflight_already_exists.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_response

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(
            mock_client, asset_id="test-asset", file_path="/path/to/test/file.exe", detonation_plan="test-plan"
        )

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "already exists in Stairwell" in results.readable_output


# AI Triage Tests
def test_ai_triage_summarize_command_success(requests_mock):
    """Test AI Triage summarize command with successful response"""
    mock_response = {
        "hash": TEST_OBJECT_ID,
        "raw": {
            "tldr": "This file is a highly suspicious executable.",
            "summary": "Detailed summary text",
            "summaryJson": {
                "malicious_likelihood": 95,
                "confidence": 90,
                "threat_type": "Trojan Dropper/Backdoor",
                "tldr": "This file is a highly suspicious executable.",
                "summary": ["Point 1", "Point 2"],
                "iocs": {
                    "urls": ["http://example.com"],
                    "file_paths_filenames": ["test.exe"],
                    "registry_keys": ["SOFTWARE\\Test"],
                },
            },
        },
    }

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json=mock_response)

    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "AI Triage Summary" in results.readable_output
    assert results.outputs.get("hash") == TEST_OBJECT_ID
    assert results.outputs.get("malicious_likelihood") == 95
    assert results.outputs.get("confidence") == 90


def test_ai_triage_summarize_command_notfound(requests_mock):
    """Test AI Triage summarize command with 404 error"""
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", status_code=404)

    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Object not found" in results.readable_output


def test_ai_triage_summarize_command_missing_args():
    """Test AI Triage summarize command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ai_triage_summarize_command(test_client_v1, "")


# Object Sightings Tests
def test_object_sightings_command_success(requests_mock):
    """Test object sightings command with successful response"""
    mock_response = {"sightings": [{"asset": {"id": "asset-1", "name": "Test Asset"}, "timestamp": "2024-01-01T00:00:00Z"}]}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", json=mock_response)

    results = object_sightings_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Sightings"
    assert "sightings" in results.outputs


def test_object_sightings_command_no_sightings(requests_mock):
    """Test object sightings command with no sightings"""
    mock_response = {"sightings": []}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", json=mock_response)

    results = object_sightings_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "No sightings found" in results.readable_output


def test_object_sightings_command_missing_args():
    """Test object sightings command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        object_sightings_command(test_client_v1, "")


# Object Detonation Trigger Tests
def test_object_detonation_trigger_command_success(requests_mock):
    """Test object detonation trigger command with successful response"""
    mock_response = {"status": "triggered", "detonation_id": "det-123"}

    requests_mock.post(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/detonation:trigger", json=mock_response)

    results = object_detonation_trigger_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Detonation triggered" in results.readable_output
    assert results.outputs_prefix == "Stairwell.Detonation.Trigger"


def test_object_detonation_trigger_command_missing_args():
    """Test object detonation trigger command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        object_detonation_trigger_command(test_client_v1, "")


# Object Detonation Get Tests
def test_object_detonation_get_command_success(requests_mock):
    """Test object detonation get command with successful response"""
    mock_response = {"status": "completed", "results": {"behavior": "malicious", "score": 95}}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/detonation", json=mock_response)

    results = object_detonation_get_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Detonation"
    assert results.outputs.get("status") == "completed"


def test_object_detonation_get_command_missing_args():
    """Test object detonation get command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        object_detonation_get_command(test_client_v1, "")


# Object Opinions Tests
def test_object_opinions_command_success(requests_mock):
    """Test object opinions command with successful response"""
    mock_response = {"opinions": [{"source": "analyst", "verdict": "malicious", "confidence": 90}]}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", json=mock_response)

    results = object_opinions_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Opinions"
    assert "opinions" in results.outputs


def test_object_opinions_command_no_opinions(requests_mock):
    """Test object opinions command with no opinions"""
    mock_response = {"opinions": []}

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", json=mock_response)

    results = object_opinions_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "No opinions found" in results.readable_output


def test_object_opinions_command_missing_args():
    """Test object opinions command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        object_opinions_command(test_client_v1, "")


# Run-To-Ground Tests
def test_run_to_ground_generate_command_success(requests_mock):
    """Test run-to-ground generate command with successful response"""
    test_client_rtg = test_client

    mock_response = {"analysis": {"objects": [TEST_OBJECT_ID, TEST_FILE_HASH], "relationships": []}}

    object_ids = f"{TEST_OBJECT_ID},{TEST_FILE_HASH}"
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", json=mock_response, status_code=200)

    results = run_to_ground_generate_command(test_client_rtg, object_ids)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.RunToGround"
    assert "analysis" in results.outputs


def test_run_to_ground_generate_command_missing_args():
    """Test run-to-ground generate command with missing arguments"""
    test_client_rtg = test_client

    with pytest.raises(DemistoException, match="Missing required arguments"):
        run_to_ground_generate_command(test_client_rtg, "")


def test_run_to_ground_generate_command_multiple_objects(requests_mock):
    """Test run-to-ground generate command with multiple object IDs"""
    test_client_rtg = test_client

    mock_response = {"analysis": {"objects": [TEST_OBJECT_ID, TEST_FILE_HASH]}}

    object_ids = f"{TEST_OBJECT_ID}, {TEST_FILE_HASH} , another-hash"
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", json=mock_response)

    results = run_to_ground_generate_command(test_client_rtg, object_ids)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.RunToGround"


# Network Intel Tests - ASN
def test_asn_get_whois_command_success(requests_mock):
    """Test ASN get whois command with successful response"""
    mock_response = {"asn": "AS12345", "organization": "Test Organization", "country": "US"}

    requests_mock.get("https://app.stairwell.com/v2/asns/12345/whois", json=mock_response)

    results = asn_get_whois_command(test_client_network, "12345")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.ASN.WHOIS"
    assert results.outputs.get("asn") == "AS12345"


def test_asn_get_whois_command_notfound(requests_mock):
    """Test ASN get whois command with 404 error"""
    requests_mock.get("https://app.stairwell.com/v2/asns/99999/whois", status_code=404)

    results = asn_get_whois_command(test_client_network, "99999")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "ASN not found" in results.readable_output


def test_asn_get_whois_command_missing_args():
    """Test ASN get whois command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        asn_get_whois_command(test_client_network, "")


# Network Intel Tests - Hostname
def test_hostname_get_command_success(requests_mock):
    """Test hostname get command with successful response"""
    mock_response = {"hostname": "example.com", "resolutions": [{"ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"}]}

    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com", json=mock_response)

    results = hostname_get_command(test_client_network, "example.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname"
    assert results.outputs.get("hostname") == "example.com"


def test_hostname_get_command_notfound(requests_mock):
    """Test hostname get command with 404 error"""
    requests_mock.get("https://app.stairwell.com/v2/hostnames/nonexistent.com", status_code=404)

    results = hostname_get_command(test_client_network, "nonexistent.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Hostname not found" in results.readable_output


def test_hostname_get_resolutions_command_success(requests_mock):
    """Test hostname get resolutions command with successful response"""
    mock_response = {
        "resolutions": [
            {"ip": "1.2.3.4", "timestamp": "2024-01-01T00:00:00Z"},
            {"ip": "5.6.7.8", "timestamp": "2024-01-02T00:00:00Z"},
        ]
    }

    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com/resolutions", json=mock_response)

    results = hostname_get_resolutions_command(test_client_network, "example.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.Resolutions"
    assert len(results.outputs.get("resolutions", [])) == 2


def test_hostname_batch_get_resolutions_command_success(requests_mock):
    """Test hostname batch get resolutions command with successful response"""
    mock_response = {"results": {"example.com": [{"ip": "1.2.3.4"}], "test.com": [{"ip": "5.6.7.8"}]}}

    requests_mock.post("https://app.stairwell.com/v2/hostnames:batch-resolutions", json=mock_response)

    results = hostname_batch_get_resolutions_command(test_client_network, "example.com,test.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.BatchResolutions"


# Network Intel Tests - IP Address
def test_ipaddress_get_command_success(requests_mock):
    """Test IP address get command with successful response"""
    mock_response = {"ip": "1.2.3.4", "country": "US", "asn": "AS12345"}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4", json=mock_response)

    results = ipaddress_get_command(test_client_network, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress"
    assert results.outputs.get("ip") == "1.2.3.4"


def test_ipaddress_lookup_cloud_provider_command_success(requests_mock):
    """Test IP address lookup cloud provider command with successful response"""
    mock_response = {"ip": "1.2.3.4", "cloud_provider": "AWS", "region": "us-east-1"}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/provider", json=mock_response)

    results = ipaddress_lookup_cloud_provider_command(test_client_network, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.CloudProvider"
    assert results.outputs.get("cloud_provider") == "AWS"


def test_ipaddress_get_hostnames_resolving_to_ip_command_success(requests_mock):
    """Test IP address get hostnames resolving to IP command with successful response"""
    mock_response = {"hostnames": ["example.com", "www.example.com"]}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/hostnames", json=mock_response)

    results = ipaddress_get_hostnames_resolving_to_ip_command(test_client_network, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.Hostnames"
    assert len(results.outputs.get("hostnames", [])) == 2


def test_ipaddress_get_whois_command_success(requests_mock):
    """Test IP address get whois command with successful response"""
    mock_response = {"ip": "1.2.3.4", "organization": "Test Org", "country": "US"}

    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/whois", json=mock_response)

    results = ipaddress_get_whois_command(test_client_network, "1.2.3.4")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.WHOIS"
    assert results.outputs.get("ip") == "1.2.3.4"


# Network Intel Tests - Utilities
def test_utilities_get_cloud_ip_ranges_command_success(requests_mock):
    """Test utilities get cloud IP ranges command with successful response"""
    mock_response = {"ranges": [{"cidr": "192.0.2.0/24", "provider": "AWS"}, {"cidr": "198.51.100.0/24", "provider": "GCP"}]}

    requests_mock.get("https://app.stairwell.com/v2/providers/ip-ranges", json=mock_response)

    results = utilities_get_cloud_ip_ranges_command(test_client_network)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CloudIPRanges"
    assert len(results.outputs.get("ranges", [])) == 2


def test_utilities_batch_canonicalize_hostnames_command_success(requests_mock):
    """Test utilities batch canonicalize hostnames command with successful response"""
    mock_response = {"results": {"EXAMPLE.COM": "example.com", "WWW.TEST.COM": "www.test.com"}}

    requests_mock.post("https://app.stairwell.com/v2/utilities/hostnames:batch-canonicalize", json=mock_response)

    results = utilities_batch_canonicalize_hostnames_command(test_client_network, "EXAMPLE.COM,WWW.TEST.COM")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedHostnames"


def test_utilities_batch_compute_etld_plus_one_command_success(requests_mock):
    """Test utilities batch compute ETLD+1 command with successful response"""
    mock_response = {"results": {"subdomain.example.com": "example.com", "www.test.co.uk": "test.co.uk"}}

    requests_mock.post("https://app.stairwell.com/v2/utilities/hostnames:batch-etld-plus-one", json=mock_response)

    results = utilities_batch_compute_etld_plus_one_command(test_client_network, "subdomain.example.com,www.test.co.uk")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.ETLDPlusOne"


def test_utilities_canonicalize_hostname_command_success(requests_mock):
    """Test utilities canonicalize hostname command with successful response"""
    mock_response = {"original": "EXAMPLE.COM", "canonicalized": "example.com"}

    requests_mock.get("https://app.stairwell.com/v2/utilities/hostnames:canonicalize/EXAMPLE.COM", json=mock_response)

    results = utilities_canonicalize_hostname_command(test_client_network, "EXAMPLE.COM")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedHostname"
    assert results.outputs.get("canonicalized") == "example.com"


def test_utilities_compute_etld_plus_one_command_success(requests_mock):
    """Test utilities compute ETLD+1 command with successful response"""
    mock_response = {"domain": "subdomain.example.com", "etld_plus_one": "example.com"}

    requests_mock.get("https://app.stairwell.com/v2/utilities/hostnames:etld-plus-one/subdomain.example.com", json=mock_response)

    results = utilities_compute_etld_plus_one_command(test_client_network, "subdomain.example.com")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.ETLDPlusOne"
    assert results.outputs.get("etld_plus_one") == "example.com"


def test_utilities_batch_canonicalize_urls_command_success(requests_mock):
    """Test utilities batch canonicalize URLs command with successful response"""
    mock_response = {"results": {"HTTPS://EXAMPLE.COM/PATH": "https://example.com/path", "HTTP://TEST.COM/": "http://test.com/"}}

    requests_mock.post("https://app.stairwell.com/v2/utilities/urls:batch-canonicalize", json=mock_response)

    results = utilities_batch_canonicalize_urls_command(test_client_network, "HTTPS://EXAMPLE.COM/PATH,HTTP://TEST.COM/")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedURLs"


def test_utilities_canonicalize_url_command_success(requests_mock):
    """Test utilities canonicalize URL command with successful response"""
    mock_response = {"original": "HTTPS://EXAMPLE.COM/PATH", "canonicalized": "https://example.com/path"}

    requests_mock.get("https://app.stairwell.com/v2/utilities/urls:canonicalize", json=mock_response)

    results = utilities_canonicalize_url_command(test_client_network, "HTTPS://EXAMPLE.COM/PATH")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Utilities.CanonicalizedURL"
    assert results.outputs.get("canonicalized") == "https://example.com/path"


# YARA Rules Tests
def test_yara_create_rule_command_success(requests_mock):
    """Test YARA create rule command with successful response"""
    TEST_ENV = "test-environment-id"
    mock_response = {
        "name": "environments/test-environment-id/yaraRules/rule-123",
        "definition": "rule simple_rule { condition: true }",
        "state": "ACTIVE",
    }

    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules", json=mock_response)

    results = yara_create_rule_command(test_client_v1_base, TEST_ENV, "rule simple_rule { condition: true }")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.YaraRule"


def test_yara_create_rule_command_missing_args():
    """Test YARA create rule command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        yara_create_rule_command(test_client_v1_base, "", "rule simple_rule { condition: true }")


def test_yara_get_rule_command_success(requests_mock):
    """Test YARA get rule command with successful response"""
    TEST_ENV = "test-environment-id"
    TEST_RULE = "rule-123"
    mock_response = {
        "name": f"environments/{TEST_ENV}/yaraRules/{TEST_RULE}",
        "definition": "rule simple_rule { condition: true }",
        "state": "ACTIVE",
        "matchCounts": {},
    }

    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}", json=mock_response)

    results = yara_get_rule_command(test_client_v1_base, TEST_ENV, TEST_RULE)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.YaraRule"


def test_yara_get_rule_command_notfound(requests_mock):
    """Test YARA get rule command with 404 error"""
    TEST_ENV = "test-environment-id"
    TEST_RULE = "nonexistent-rule"

    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}", status_code=404)

    results = yara_get_rule_command(test_client_v1_base, TEST_ENV, TEST_RULE)

    assert isinstance(results, CommandResults)
    assert results.readable_output


def test_yara_query_matches_command_success(requests_mock):
    """Test YARA query matches command with successful response"""
    TEST_ENV = "test-environment-id"
    TEST_RULE = "rule-123"
    mock_response = {
        "objects": [
            {"sha256": TEST_FILE_HASH, "md5": "abc123", "sha1": "def456"},
        ],
        "nextPageToken": "",
    }

    requests_mock.get(
        f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}/matchingObjects", json=mock_response
    )

    results = yara_query_matches_command(test_client_v1_base, TEST_ENV, TEST_RULE)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.YaraRuleMatches"


# Asset Management Tests
def test_asset_list_command_success(requests_mock):
    """Test asset list command with successful response"""
    TEST_ENV = "test-environment-id"
    mock_response = {
        "assets": [
            {"name": "assets/VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6", "label": "test-endpoint"},
            {"name": "assets/XXXX-YYYY-ZZZZ", "label": "another-endpoint"},
        ]
    }

    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json=mock_response)

    results = asset_list_command(test_client_v1_base, TEST_ENV)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Assets"


def test_asset_list_command_missing_args():
    """Test asset list command with missing arguments"""
    with pytest.raises(DemistoException, match="Missing required arguments"):
        asset_list_command(test_client_v1_base, "")


def test_asset_create_command_success(requests_mock):
    """Test asset create command with successful response"""
    TEST_ENV = "test-environment-id"
    mock_response = {"name": "assets/VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6", "label": "test-endpoint", "uploadToken": "token-abc-123"}

    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json=mock_response)

    results = asset_create_command(test_client_v1_base, TEST_ENV, "test-endpoint")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Asset"


def test_asset_get_command_success(requests_mock):
    """Test asset get command with successful response"""
    TEST_ASSET = "VPNB84-P9L3H4-QDTEFJ-JCJ2U8A6"
    mock_response = {"name": f"assets/{TEST_ASSET}", "label": "test-endpoint", "uploadToken": "token-abc-123"}

    requests_mock.get(f"https://app.stairwell.com/v1/assets/{TEST_ASSET}", json=mock_response)

    results = asset_get_command(test_client_v1_base, TEST_ASSET)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Asset"


def test_asset_get_command_notfound(requests_mock):
    """Test asset get command with 404 error"""
    TEST_ASSET = "NONEXISTENT-ASSET-ID"

    requests_mock.get(f"https://app.stairwell.com/v1/assets/{TEST_ASSET}", status_code=404)

    results = asset_get_command(test_client_v1_base, TEST_ASSET)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "not found" in results.readable_output.lower()


# ─────────────────────────────────────────────
# _resolve_file_source Tests
# ─────────────────────────────────────────────


def test_resolve_file_source_no_source():
    _, _, err = _resolve_file_source()
    assert "Missing file source" in err


def test_resolve_file_source_multiple_sources():
    _, _, err = _resolve_file_source(url="http://x.com/f", file_path="/x")
    assert "Multiple file sources" in err


def test_resolve_file_source_file_path_success():
    with tempfile.NamedTemporaryFile() as f:
        path, name, err = _resolve_file_source(file_path=f.name)
    assert err is None
    assert path == f.name


def test_resolve_file_source_file_path_not_found():
    _, _, err = _resolve_file_source(file_path="/no/such/path/at/all.bin")
    assert "File not found" in err


def test_resolve_file_source_entry_id_success():
    with (
        patch("Stairwell.demisto.getFilePath", return_value={"path": "/tmp/f.exe", "name": "f.exe"}),
        patch("Stairwell.os.path.exists", return_value=True),
    ):
        path, name, err = _resolve_file_source(entry_id="123@4")
    assert err is None
    assert path == "/tmp/f.exe"
    assert name == "f.exe"


def test_resolve_file_source_entry_id_file_not_on_disk():
    with (
        patch("Stairwell.demisto.getFilePath", return_value={"path": "/tmp/missing.exe", "name": "f.exe"}),
        patch("Stairwell.os.path.exists", return_value=False),
    ):
        _, _, err = _resolve_file_source(entry_id="123@4")
    assert "not found at" in err


def test_resolve_file_source_entry_id_no_path_in_response():
    with patch("Stairwell.demisto.getFilePath", return_value={"name": "f.exe"}):
        _, _, err = _resolve_file_source(entry_id="123@4")
    assert "no path in response" in err


def test_resolve_file_source_entry_id_invalid_response():
    with patch("Stairwell.demisto.getFilePath", return_value="not a dict"):
        _, _, err = _resolve_file_source(entry_id="123@4")
    assert "invalid response" in err


def test_resolve_file_source_entry_id_exception():
    with patch("Stairwell.demisto.getFilePath", side_effect=Exception("boom")):
        _, _, err = _resolve_file_source(entry_id="123@4")
    assert "Failed to resolve entry ID" in err


def test_resolve_file_source_url_invalid_scheme():
    _, _, err = _resolve_file_source(url="ftp://example.com/file.exe")
    assert "Invalid URL scheme" in err


def test_resolve_file_source_url_success():
    mock_resp = MagicMock()
    mock_resp.iter_content.return_value = [b"chunk1", b"chunk2"]
    mock_resp.raise_for_status.return_value = None
    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp
    with patch("Stairwell._create_session_with_retries", return_value=mock_session):
        path, name, err = _resolve_file_source(url="https://example.com/malware.exe")
    assert err is None
    assert name == "malware.exe"
    if path and os.path.exists(path):
        os.unlink(path)


def test_resolve_file_source_url_no_filename_in_path():
    mock_resp = MagicMock()
    mock_resp.iter_content.return_value = [b"data"]
    mock_resp.raise_for_status.return_value = None
    mock_session = MagicMock()
    mock_session.get.return_value = mock_resp
    with patch("Stairwell._create_session_with_retries", return_value=mock_session):
        path, name, err = _resolve_file_source(url="https://example.com/")
    assert err is None
    assert name == "downloaded_file"
    if path and os.path.exists(path):
        os.unlink(path)


def test_resolve_file_source_url_timeout():
    mock_session = MagicMock()
    mock_session.get.side_effect = requests.exceptions.Timeout()
    with patch("Stairwell._create_session_with_retries", return_value=mock_session):
        _, _, err = _resolve_file_source(url="https://example.com/file.exe")
    assert "Timeout downloading" in err


def test_resolve_file_source_url_connection_error():
    mock_session = MagicMock()
    mock_session.get.side_effect = requests.exceptions.ConnectionError("conn refused")
    with patch("Stairwell._create_session_with_retries", return_value=mock_session):
        _, _, err = _resolve_file_source(url="https://example.com/file.exe")
    assert "Connection error" in err


def test_resolve_file_source_url_request_exception():
    mock_session = MagicMock()
    mock_session.get.side_effect = requests.exceptions.RequestException("generic error")
    with patch("Stairwell._create_session_with_retries", return_value=mock_session):
        _, _, err = _resolve_file_source(url="https://example.com/file.exe")
    assert "Failed to download" in err


# ─────────────────────────────────────────────
# _parse_int_arg Tests
# ─────────────────────────────────────────────


def test_parse_int_arg_none():
    assert _parse_int_arg(None, "test") is None


def test_parse_int_arg_valid():
    assert _parse_int_arg("42", "pageSize") == 42


def test_parse_int_arg_negative_not_allowed():
    with pytest.raises(DemistoException):
        _parse_int_arg("-1", "pageSize")


def test_parse_int_arg_not_integer():
    with pytest.raises(DemistoException):
        _parse_int_arg("abc", "pageSize")


def test_parse_int_arg_negative_allowed():
    assert _parse_int_arg("-5", "offset", allow_negative=True) == -5


# ─────────────────────────────────────────────
# _hash_sha256 Tests
# ─────────────────────────────────────────────


def test_hash_sha256_error():
    sha, err = _hash_sha256("/nonexistent/file.bin")
    assert sha is None
    assert err is not None


def test_hash_sha256_success():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test content")
        tmp_path = f.name
    try:
        sha, err = _hash_sha256(tmp_path)
        assert err is None
        assert sha is not None
        assert len(sha) == 64
    finally:
        os.unlink(tmp_path)


# ─────────────────────────────────────────────
# intake_preflight_and_upload Additional Paths
# ─────────────────────────────────────────────


def test_intake_preflight_and_upload_unexpected_preflight_response():
    """Preflight returns response with no fileActions key"""
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = {"someOther": "data"}
    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/file.exe")
    assert "Unexpected preflight response" in results.readable_output


def test_intake_preflight_and_upload_preflight_timeout():
    """Preflight request times out"""
    mock_client = MagicMock()
    mock_client.intake_preflight.side_effect = requests.exceptions.Timeout()
    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/file.exe")
    assert "timed out" in results.readable_output


def test_intake_preflight_and_upload_preflight_connection_error():
    """Preflight request gets a connection error"""
    mock_client = MagicMock()
    mock_client.intake_preflight.side_effect = requests.exceptions.ConnectionError("refused")
    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/file.exe")
    assert "Connection error" in results.readable_output


def test_intake_preflight_and_upload_resolve_error():
    """_resolve_file_source returns an error"""
    with patch("Stairwell._resolve_file_source", return_value=(None, None, "File not found at path: /bad")):
        results = intake_preflight_and_upload(test_intake_client, asset_id="test-asset", file_path="/bad/path")
    assert "File not found" in results.readable_output


def test_intake_preflight_and_upload_hash_error():
    """SHA256 calculation fails"""
    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=(None, "Failed computing sha256")),
    ):
        results = intake_preflight_and_upload(test_intake_client, asset_id="test-asset", file_path="/path/file.exe")
    assert "Failed computing sha256" in results.readable_output


# ─────────────────────────────────────────────
# Missing Args Tests for Network Intel Commands
# ─────────────────────────────────────────────


def test_hostname_get_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        hostname_get_command(test_client_network, "")


def test_hostname_get_resolutions_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        hostname_get_resolutions_command(test_client_network, "")


def test_hostname_batch_get_resolutions_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        hostname_batch_get_resolutions_command(test_client_network, "")


def test_ipaddress_get_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_get_command(test_client_network, "")


def test_ipaddress_lookup_cloud_provider_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_lookup_cloud_provider_command(test_client_network, "")


def test_ipaddress_get_hostnames_resolving_to_ip_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_get_hostnames_resolving_to_ip_command(test_client_network, "")


def test_ipaddress_get_whois_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        ipaddress_get_whois_command(test_client_network, "")


def test_utilities_batch_canonicalize_hostnames_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_batch_canonicalize_hostnames_command(test_client_network, "")


def test_utilities_batch_compute_etld_plus_one_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_batch_compute_etld_plus_one_command(test_client_network, "")


def test_utilities_canonicalize_hostname_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_canonicalize_hostname_command(test_client_network, "")


def test_utilities_compute_etld_plus_one_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_compute_etld_plus_one_command(test_client_network, "")


def test_utilities_batch_canonicalize_urls_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_batch_canonicalize_urls_command(test_client_network, "")


def test_utilities_canonicalize_url_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        utilities_canonicalize_url_command(test_client_network, "")


# ─────────────────────────────────────────────
# YARA Command Error Paths
# ─────────────────────────────────────────────


def test_yara_create_rule_command_400(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules", status_code=400)
    results = yara_create_rule_command(test_client_v1_base, TEST_ENV, "rule bad { }")
    assert "Invalid YARA rule" in results.readable_output


def test_yara_create_rule_command_403(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules", status_code=403)
    results = yara_create_rule_command(test_client_v1_base, TEST_ENV, "rule x { condition: true }")
    assert "Permission denied" in results.readable_output


def test_yara_query_matches_command_no_results(requests_mock):
    TEST_ENV = "test-environment-id"
    TEST_RULE = "rule-123"
    requests_mock.get(
        f"https://app.stairwell.com/v1/environments/{TEST_ENV}/yaraRules/{TEST_RULE}/matchingObjects",
        json={"objects": [], "nextPageToken": ""},
    )
    results = yara_query_matches_command(test_client_v1_base, TEST_ENV, TEST_RULE)
    assert "No matches found" in results.readable_output


def test_yara_query_matches_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        yara_query_matches_command(test_client_v1_base, "", "rule-123")


# ─────────────────────────────────────────────
# Asset Command Error Paths
# ─────────────────────────────────────────────


def test_asset_create_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        asset_create_command(test_client_v1_base, "test-env", "")


def test_asset_list_command_no_assets(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", json={"assets": []})
    results = asset_list_command(test_client_v1_base, TEST_ENV)
    assert "No assets found" in results.readable_output


def test_asset_list_command_404(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.get(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=404)
    results = asset_list_command(test_client_v1_base, TEST_ENV)
    assert "Environment not found" in results.readable_output


def test_asset_create_command_400(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=400)
    results = asset_create_command(test_client_v1_base, TEST_ENV, "bad-label")
    assert "Invalid asset parameters" in results.readable_output


def test_asset_create_command_403(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=403)
    results = asset_create_command(test_client_v1_base, TEST_ENV, "test-label")
    assert "Permission denied" in results.readable_output


def test_asset_create_command_409(requests_mock):
    TEST_ENV = "test-environment-id"
    requests_mock.post(f"https://app.stairwell.com/v1/environments/{TEST_ENV}/assets", status_code=409)
    results = asset_create_command(test_client_v1_base, TEST_ENV, "duplicate-label")
    assert "already exist" in results.readable_output


# ─────────────────────────────────────────────
# Object Command Error Paths
# ─────────────────────────────────────────────


def test_object_sightings_command_404(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/sightings", status_code=404)
    results = object_sightings_command(test_client_v1, TEST_OBJECT_ID)
    assert "Object not found" in results.readable_output


def test_object_opinions_command_404(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/opinions", status_code=404)
    results = object_opinions_command(test_client_v1, TEST_OBJECT_ID)
    assert "Object not found" in results.readable_output


def test_object_detonation_trigger_command_404(requests_mock):
    requests_mock.post(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/detonation:trigger", status_code=404)
    results = object_detonation_trigger_command(test_client_v1, TEST_OBJECT_ID)
    assert "Object not found" in results.readable_output


def test_object_detonation_get_command_404(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}/detonation", status_code=404)
    results = object_detonation_get_command(test_client_v1, TEST_OBJECT_ID)
    assert "No detonation results found" in results.readable_output


def test_ai_triage_summarize_command_400(requests_mock):
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", status_code=400)
    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)
    assert "Invalid request" in results.readable_output


def test_run_to_ground_generate_command_400(requests_mock):
    test_client_rtg = test_client
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", status_code=400)
    results = run_to_ground_generate_command(test_client_rtg, TEST_OBJECT_ID)
    assert "Invalid object IDs" in results.readable_output


def test_run_to_ground_generate_command_404(requests_mock):
    test_client_rtg = test_client
    requests_mock.get("https://app.stairwell.com/v1/generateRunToGround:generate", status_code=404)
    results = run_to_ground_generate_command(test_client_rtg, TEST_OBJECT_ID)
    assert "not found" in results.readable_output.lower()


# ─────────────────────────────────────────────
# Optional Parameter Coverage
# ─────────────────────────────────────────────


def test_hostname_get_command_with_record_type(requests_mock):
    mock_response = {"hostname": "example.com", "records": []}
    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com", json=mock_response)
    results = hostname_get_command(test_client_network, "example.com", record_type="A")
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname"


def test_hostname_get_resolutions_with_time_params(requests_mock):
    mock_response = {"resolutions": []}
    requests_mock.get("https://app.stairwell.com/v2/hostnames/example.com/resolutions", json=mock_response)
    results = hostname_get_resolutions_command(
        test_client_network,
        "example.com",
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-12-31T00:00:00Z",
    )
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.Resolutions"


def test_ipaddress_get_hostnames_resolving_to_ip_with_time_params(requests_mock):
    mock_response = {"hostnames": ["example.com"]}
    requests_mock.get("https://app.stairwell.com/v2/ips/1.2.3.4/hostnames", json=mock_response)
    results = ipaddress_get_hostnames_resolving_to_ip_command(
        test_client_network,
        "1.2.3.4",
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-12-31T00:00:00Z",
    )
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.IPAddress.Hostnames"


def test_ipaddress_get_command_404(requests_mock):
    requests_mock.get("https://app.stairwell.com/v2/ips/9.9.9.9", status_code=404)
    results = ipaddress_get_command(test_client_network, "9.9.9.9")
    assert "IP address not found" in results.readable_output


def test_hostname_get_resolutions_command_404(requests_mock):
    requests_mock.get("https://app.stairwell.com/v2/hostnames/nonexistent.com/resolutions", status_code=404)
    results = hostname_get_resolutions_command(test_client_network, "nonexistent.com")
    assert isinstance(results, CommandResults)
    assert results.readable_output


def test_asn_get_whois_command_adds_asn_to_response(requests_mock):
    """Test ASN WHOIS when response lacks 'asn' key — code should inject it"""
    mock_response = {"organization": "Test Org"}  # no "asn" key
    requests_mock.get("https://app.stairwell.com/v2/asns/99/whois", json=mock_response)
    results = asn_get_whois_command(test_client_network, "99")
    assert results.outputs.get("asn") == "99"


def test_yara_get_rule_command_missing_args():
    with pytest.raises(DemistoException, match="Missing required arguments"):
        yara_get_rule_command(test_client_v1_base, "", "rule-123")


def test_ai_triage_summarize_command_no_raw_data(requests_mock):
    """Test AI triage when response has no 'raw' field"""
    mock_response = {"hash": TEST_OBJECT_ID}
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json=mock_response)
    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs.get("hash") == TEST_OBJECT_ID


def test_ai_triage_summarize_command_non_dict_response(requests_mock):
    """Test AI triage when response is not a dict"""
    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json="unexpected string")
    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)
    assert isinstance(results, CommandResults)
    assert results.readable_output


# ─────────────────────────────────────────────
# AI Triage — Rich Response (conditional branch coverage)
# ─────────────────────────────────────────────


def test_ai_triage_summarize_command_rich_response(requests_mock):
    """Test AI triage with all optional summaryJson fields populated"""
    mock_response = {
        "hash": TEST_OBJECT_ID,
        "raw": {
            "tldr": "Suspicious executable",
            "summary": "Very long detailed analysis " * 20,
            "summaryJson": {
                "malicious_likelihood": 99,
                "confidence": 95,
                "threat_type": "Backdoor",
                "tldr": "Suspicious executable",
                "summary": ["Point 1"],
                "iocs": {
                    "urls": ["http://evil.com"],
                    "file_paths_filenames": [f"file{i}.exe" for i in range(25)],  # >20 to trigger truncation
                    "registry_keys": ["SOFTWARE\\Bad"],
                    "ip_addresses": ["198.51.100.1", "203.0.113.1"],
                },
                "key_considerations": {
                    "prevalence": "Rare malware family",
                    "api_analysis": "Uses suspicious Windows APIs",
                    "entropy_analysis": "High entropy sections detected",
                },
                "guidance_for_clarity_and_impact": {
                    "persistence_mechanisms": ["Registry run key", "Scheduled task"],
                    "obfuscation_or_evasion_techniques": ["Packing", "Anti-debug"],
                    "data_exfiltration_capabilities": ["HTTP POST to C2"],
                },
            },
        },
    }

    requests_mock.get(f"https://app.stairwell.com/v1/objects/{TEST_OBJECT_ID}:summarize", json=mock_response)
    results = ai_triage_summarize_command(test_client_v1, TEST_OBJECT_ID)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Suspicious executable" in results.readable_output
    assert "Prevalence" in results.readable_output
    assert "API Analysis" in results.readable_output
    assert "Entropy Analysis" in results.readable_output
    assert "Persistence Mechanisms" in results.readable_output
    assert "IP Addresses" in results.readable_output


# ─────────────────────────────────────────────
# Intake — Upload Step Failures
# ─────────────────────────────────────────────


def test_intake_preflight_and_upload_upload_timeout(requests_mock):
    """Upload step times out after preflight succeeds"""
    mock_preflight = util_load_json("test_data/intake_preflight_upload.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_preflight

    requests_mock.post("https://storage.googleapis.com/upload-url", exc=requests.exceptions.Timeout())

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"fake content")
        tmp_path = tmp.name

    try:
        with patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)):
            results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path=tmp_path)
    finally:
        os.unlink(tmp_path)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "timed out" in results.readable_output
    assert results.outputs.get("error") == "upload_timeout"


def test_intake_preflight_and_upload_upload_connection_error(requests_mock):
    """Upload step gets a connection error after preflight succeeds"""
    mock_preflight = util_load_json("test_data/intake_preflight_upload.json")
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = mock_preflight

    requests_mock.post("https://storage.googleapis.com/upload-url", exc=requests.exceptions.ConnectionError("refused"))

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
        tmp.write(b"fake content")
        tmp_path = tmp.name

    try:
        with patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)):
            results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path=tmp_path)
    finally:
        os.unlink(tmp_path)

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "Connection error during file upload" in results.readable_output


def test_intake_preflight_and_upload_http_error_outer():
    """Outer requests.HTTPError catch (not DemistoException) in intake"""
    mock_client = MagicMock()
    mock_client.intake_preflight.side_effect = requests.exceptions.HTTPError("500 Server Error")

    with (
        patch("Stairwell.os.path.exists", return_value=True),
        patch("Stairwell._hash_sha256", return_value=("abc123fakehash", None)),
    ):
        results = intake_preflight_and_upload(mock_client, asset_id="test-asset", file_path="/path/to/test/file.exe")

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "HTTP error during Intake preflight/upload" in results.readable_output


def test_intake_preflight_and_upload_with_entry_id():
    """Intake with entry_id source covers the entry_id branch in markdown"""
    mock_client = MagicMock()
    mock_client.intake_preflight.return_value = util_load_json("test_data/intake_preflight_already_exists.json")

    with patch("Stairwell._resolve_file_source", return_value=("/tmp/fake.exe", "fake.exe", None)):
        results = intake_preflight_and_upload(
            mock_client,
            asset_id="test-asset",
            entry_id="abc123",
            sha256="e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d",
        )

    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "already exists in Stairwell" in results.readable_output


# ─────────────────────────────────────────────
# Cloud IP Ranges — Exception Paths
# ─────────────────────────────────────────────


def test_utilities_get_cloud_ip_ranges_400():
    """Cloud IP ranges 400 error (invalid provider)"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("400 Bad Request")
    results = utilities_get_cloud_ip_ranges_command(mock_client, provider="invalid-provider")
    assert "Invalid provider parameter" in results.readable_output


def test_utilities_get_cloud_ip_ranges_400_no_provider():
    """Cloud IP ranges 400 error (no provider)"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("400 Bad Request")
    results = utilities_get_cloud_ip_ranges_command(mock_client)
    assert "Bad request" in results.readable_output


def test_utilities_get_cloud_ip_ranges_404():
    """Cloud IP ranges 404 error (provider not found)"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("404 Not Found")
    results = utilities_get_cloud_ip_ranges_command(mock_client, provider="FakeProvider")
    assert "not found" in results.readable_output.lower()


def test_utilities_get_cloud_ip_ranges_other_exception():
    """Cloud IP ranges unexpected error raises"""
    mock_client = MagicMock()
    mock_client.get_cloud_ip_ranges.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_get_cloud_ip_ranges_command(mock_client)


def test_utilities_get_cloud_ip_ranges_with_provider(requests_mock):
    """Cloud IP ranges with provider param exercises the provider branch"""
    mock_response = {"ranges": [{"cidr": "192.0.2.0/24", "provider": "AWS"}]}
    requests_mock.get("https://app.stairwell.com/v2/providers/AWS/ip-ranges", json=mock_response)
    results = utilities_get_cloud_ip_ranges_command(test_client_network, provider="AWS")
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert "AWS" in results.readable_output


# ─────────────────────────────────────────────
# Utilities — Exception Re-raise Paths
# ─────────────────────────────────────────────


def test_utilities_batch_canonicalize_hostnames_400():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_hostnames.side_effect = DemistoException("400 Bad Request")
    results = utilities_batch_canonicalize_hostnames_command(mock_client, "bad..host,other")
    assert "Invalid hostname format" in results.readable_output


def test_utilities_batch_canonicalize_hostnames_other_exception():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_hostnames.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_batch_canonicalize_hostnames_command(mock_client, "example.com")


def test_utilities_batch_compute_etld_plus_one_400():
    mock_client = MagicMock()
    mock_client.batch_compute_etld_plus_one.side_effect = DemistoException("400 Bad Request")
    results = utilities_batch_compute_etld_plus_one_command(mock_client, "bad..domain")
    assert "Invalid domain format" in results.readable_output


def test_utilities_batch_compute_etld_plus_one_other_exception():
    mock_client = MagicMock()
    mock_client.batch_compute_etld_plus_one.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_batch_compute_etld_plus_one_command(mock_client, "example.com")


def test_utilities_canonicalize_hostname_400():
    mock_client = MagicMock()
    mock_client.canonicalize_hostname.side_effect = DemistoException("400 Bad Request")
    results = utilities_canonicalize_hostname_command(mock_client, "bad..host")
    assert "Invalid hostname format" in results.readable_output


def test_utilities_canonicalize_hostname_other_exception():
    mock_client = MagicMock()
    mock_client.canonicalize_hostname.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_canonicalize_hostname_command(mock_client, "example.com")


def test_utilities_compute_etld_plus_one_400():
    mock_client = MagicMock()
    mock_client.compute_etld_plus_one.side_effect = DemistoException("400 Bad Request")
    results = utilities_compute_etld_plus_one_command(mock_client, "bad..domain")
    assert "Invalid domain format" in results.readable_output


def test_utilities_compute_etld_plus_one_other_exception():
    mock_client = MagicMock()
    mock_client.compute_etld_plus_one.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_compute_etld_plus_one_command(mock_client, "example.com")


def test_utilities_batch_canonicalize_urls_400():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_urls.side_effect = DemistoException("400 Bad Request")
    results = utilities_batch_canonicalize_urls_command(mock_client, "not-a-url")
    assert "Invalid URL format" in results.readable_output


def test_utilities_batch_canonicalize_urls_other_exception():
    mock_client = MagicMock()
    mock_client.batch_canonicalize_urls.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_batch_canonicalize_urls_command(mock_client, "https://example.com")


def test_utilities_canonicalize_url_400():
    mock_client = MagicMock()
    mock_client.canonicalize_url.side_effect = DemistoException("400 Bad Request")
    results = utilities_canonicalize_url_command(mock_client, "not-a-url")
    assert "Invalid URL format" in results.readable_output


def test_utilities_canonicalize_url_other_exception():
    mock_client = MagicMock()
    mock_client.canonicalize_url.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        utilities_canonicalize_url_command(mock_client, "https://example.com")


# ─────────────────────────────────────────────
# Network Intel — Non-404 Exception Re-raises
# ─────────────────────────────────────────────


def test_ipaddress_lookup_cloud_provider_non_404():
    mock_client = MagicMock()
    mock_client.lookup_cloud_provider.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        ipaddress_lookup_cloud_provider_command(mock_client, "1.2.3.4")


def test_ipaddress_get_hostnames_resolving_to_ip_non_404():
    mock_client = MagicMock()
    mock_client.get_hostnames_resolving_to_ip.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        ipaddress_get_hostnames_resolving_to_ip_command(mock_client, "1.2.3.4")


def test_ipaddress_get_whois_non_404():
    mock_client = MagicMock()
    mock_client.get_ip_address_whois.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        ipaddress_get_whois_command(mock_client, "1.2.3.4")


def test_hostname_batch_get_resolutions_raises():
    mock_client = MagicMock()
    mock_client.batch_get_hostname_resolutions.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        hostname_batch_get_resolutions_command(mock_client, "example.com")


# ─────────────────────────────────────────────
# Batch Hostname Resolutions — With Data
# ─────────────────────────────────────────────


def test_hostname_batch_get_resolutions_with_data(requests_mock):
    """Batch resolutions with actual resolution data exercises lines 1015-1023"""
    mock_response = {
        "resolutions": [
            {
                "reversedHostname": "com.example",
                "resolutions": [{"ipAddress": "93.184.216.34", "recordType": "A", "timestamp": "2024-01-01T00:00:00Z"}],
            }
        ]
    }
    requests_mock.post(
        "https://app.stairwell.com/v2/hostnames:batch-resolutions",
        json=mock_response,
    )
    results = hostname_batch_get_resolutions_command(test_client_network, "example.com")
    assert isinstance(results, CommandResults)
    assert results.readable_output
    assert results.outputs_prefix == "Stairwell.Hostname.BatchResolutions"


# ─────────────────────────────────────────────
# File Enrichment / Variant — Non-standard Exception Re-raises
# ─────────────────────────────────────────────


def test_file_enrichment_command_non_404():
    """file_enrichment_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.get_file_reputation.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        file_enrichment_command(mock_client, TEST_FILE_HASH)


def test_variant_discovery_command_non_500():
    """variant_discovery_command re-raises non-500 DemistoException"""
    mock_client = MagicMock()
    mock_client.get_file_variants.side_effect = DemistoException("403 Forbidden")
    with pytest.raises(DemistoException):
        variant_discovery_command(mock_client, TEST_FILE_HASH)


# ─────────────────────────────────────────────
# Asset / YARA — Non-404 Exception Re-raises
# ─────────────────────────────────────────────


def test_asset_list_command_non_404():
    """asset_list_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.list_assets.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        asset_list_command(mock_client, "test-env")


def test_asset_get_command_non_404():
    """asset_get_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.get_asset.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        asset_get_command(mock_client, "test-asset")


def test_yara_query_matches_command_non_404():
    """yara_query_matches_command re-raises non-404 DemistoException"""
    mock_client = MagicMock()
    mock_client.query_yara_matches.side_effect = DemistoException("503 Service Unavailable")
    with pytest.raises(DemistoException):
        yara_query_matches_command(mock_client, "test-env", "test-rule")


# Status code helper tests
def test_status_code_prefers_response_object():
    """_status_code reads the attached response first."""
    err = DemistoException("Error in API call [404] - Not Found", res=MagicMock(status_code=500))
    assert _status_code(err) == 500


def test_status_code_falls_back_to_message_marker():
    """_status_code parses the [NNN] marker BaseClient writes when no response is attached."""
    assert _status_code(DemistoException("Error in API call [404] - Not Found")) == 404
    assert _status_code(DemistoException("500 Server Error")) == 500
    assert _status_code(DemistoException("Connection refused")) is None


def test_status_code_ignores_digits_in_hash():
    """A hash containing '404' must not be mistaken for a 404 response."""
    err = DemistoException("Error in API call [500] - object abc404def not found")
    assert _status_code(err) == 500


def test_file_enrichment_command_500_is_raised(requests_mock):
    """A real server error must surface as an error, not as 'File not found'."""
    requests_mock.get("https://reputation.app.stairwell.com/api/v3/files/" + TEST_FILE_HASH, status_code=500, text="hash 404abc")
    with pytest.raises(DemistoException):
        file_enrichment_command(test_client, TEST_FILE_HASH)


def test_test_module_auth_error(requests_mock):
    """test_module reports an authorization problem on 401."""
    requests_mock.get(
        "https://reputation.app.stairwell.com/api/v3/files/e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d",
        status_code=401,
    )
    assert run_test_module(test_client) == "Authorization Error: make sure API Key is correctly set"


def test_test_module_ok(requests_mock):
    """test_module returns ok on a well-formed reputation response."""
    requests_mock.get(
        "https://reputation.app.stairwell.com/api/v3/files/e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d",
        json={"data": {"attributes": {"sha256": "x"}}},
    )
    assert run_test_module(test_client) == "ok"

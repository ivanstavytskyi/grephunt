from grephunt.config import max_image_upload_bytes, max_upload_bytes, upload_limit_label


def test_default_upload_limits_are_ten_gb():
    assert max_upload_bytes() == 10_240 * 1_000_000
    assert max_image_upload_bytes() == 10_240 * 1_000_000
    assert upload_limit_label(max_upload_bytes()) == "10 GB"

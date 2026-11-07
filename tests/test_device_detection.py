import pytest

from scanner.device_detection import is_randomized_mac


# ── Case 1: a real vendor MAC is not randomized ─────────────────────
def test_vendor_mac_is_not_randomized():
    assert is_randomized_mac("b8:27:eb:9f:12:34") is False


# ── Case 2: the iPhone in the demo data uses a private MAC ──────────
def test_demo_iphone_mac_is_randomized():
    assert is_randomized_mac("da:a1:19:4c:22:7e") is True


# ── Case 3: the rule ────────────────────────────────────────────────
# A MAC is randomized when the SECOND hex digit is 2, 6, A or E.
# In binary those are 0010, 0110, 1010, 1110: all have the "2" bit set,
# which is the "locally administered" flag.
@pytest.mark.parametrize("mac", [
    "02:00:00:00:00:01",   # second digit 2
    "06:00:00:00:00:01",   # second digit 6
    "0a:00:00:00:00:01",   # second digit A
    "0e:00:00:00:00:01",   # second digit E
])
def test_second_digit_2_6_a_e_means_randomized(mac):
    assert is_randomized_mac(mac) is True


# 0000, 0100, 1000: the "2" bit is clear.
@pytest.mark.parametrize("mac", [
    "00:00:00:00:00:01",   # second digit 0
    "04:00:00:00:00:01",   # second digit 4
    "08:00:00:00:00:01",   # second digit 8
])
def test_other_second_digits_are_not_randomized(mac):
    assert is_randomized_mac(mac) is False


# ── Case 4: uppercase letters ───────────────────────────────────────
def test_uppercase_mac_works():
    assert is_randomized_mac("DA:A1:19:4C:22:7E") is True


# ── Case 5: nothing to check ────────────────────────────────────────
@pytest.mark.parametrize("mac", ["", None])
def test_empty_input_is_not_randomized(mac):
    assert is_randomized_mac(mac) is False


# ── Case 6: Windows style, with dashes ──────────────────────────────
def test_mac_with_dashes():
    # Same address as Case 4, just written the Windows way,
    # so the answer should be the same: randomized.
    assert is_randomized_mac("DA-A1-19-4C-22-7E") is True


# ── Found by Case 6: other notations and junk input ─────────────────
@pytest.mark.parametrize("mac", [
    "DA-A1-19-4C-22-7E",   # Windows
    "daa1.194c.227e",      # Cisco
])
def test_other_notations_work(mac):
    assert is_randomized_mac(mac) is True


@pytest.mark.parametrize("mac", [
    "not a mac",
    "zz:zz:zz:zz:zz:zz",
    "da:a1:19",            # too short
])
def test_junk_input_returns_false_instead_of_crashing(mac):
    assert is_randomized_mac(mac) is False

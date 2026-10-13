from prototype import check_rulebook
import pytest

# These tests check the rulebook section for different parameters that may be found in powershell commands
# First, testing all the parameters
@pytest.mark.parametrize( "text, expected_label",
                         [("powershell.exe -enc SHJVAVSSGHH","Command was Encoded"),
                          ("powershell.exe -encryption SHJVAVSSGHH","Command was Encoded"),
                          ("curl -0 https://test.com/test","Command downloaded Content from the web"),
                          ("Invoke-Expression $Command","Command executed text as script"),
                          ("powershell.exe -WindowStyle Hidden","Powershell Window is Hidden"),
                          ("[Text.Encoding]::Utf8.GetString([Covert]::FromBase64String(''))","Base64 Encoded Command"),
                          ("Mimikatz # privilage::debug","Mimikatz installed on system"),
                          ("vssadmin delete shadows","Shadow Copies Deleted"),    
                         ])
def test_each_section(text,expected_label):
    labels, _ = check_rulebook(text)
    assert expected_label in labels

# Second, testing edge cases 
def test_score_zero():
    label, score = check_rulebook("C:\\Program Files\\Onedrive\\OneDrive.exe /background")
    assert label == [] 
    assert score == 0

def test_multiple_score_add():
    label, score = check_rulebook("powershell.exe -enc AHSGHAs; iex $")
    assert len(label) == 2
    assert score == 7

def test_case():
    label, score = check_rulebook("MIMIKATZ # PRIVILAGE::DEBUG") 
    assert "Mimikatz installed on system" in label
    assert score == 4

# All tests come back passed.
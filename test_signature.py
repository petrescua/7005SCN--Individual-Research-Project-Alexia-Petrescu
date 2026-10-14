from prototype import check_signature
import pytest

# This function takes in a path, and checks the current signature of the path
# If it has been signed by a certified authroity, it will come back as Valid, meaning the path should be safe

# Test checks if known valid path returns valid
def test_path():
    path = r"C:\Program Files\Microsoft OneDrive\OneDrive.App.exe"
    assert check_signature(path) == "Valid"

# Test checks if non valid path returns non valid output
@pytest.mark.parametrize("path",
                         [("C:\\Users\\vboxuser\\Desktop\\Macros\\DetectMacros.py"),
                          ("C:\\Windows\\Fonts"),
                          ("Not_a_Path"),
                             
                         ])
def test_invalid_path(path):
    assert check_signature(path) == f"Unknown, likely unable to validate. Input was: {path}"


# All Test Passed
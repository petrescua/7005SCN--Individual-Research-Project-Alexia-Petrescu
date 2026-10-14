from prototype import shortcut_path
import pytest

# This function check the location a shortcut will show to

# First, checking the function fully delivers on a location when a lnk file is shown
# This link file was created for this test, and it runs back to notepad.
def test_lnk_path():
    lnk = r"C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\test.lnk"
    assert shortcut_path(lnk) == r"C:\Windows\System32\notepad.exe"

# Then, checking multiple non-link paths that exists, as well as non-paths
# This returns none as it raises an Execption
@pytest.mark.parametrize("lnk",
                         [("C:\\Users\\vboxuser\\Downloads\\Macro_setup.docx"),
                          ("C:\\Program Files\\Microsoft OneDrive\\OneDrive.App.exe"),
                          ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"),
                          ("Not_A_Path_Test"),
                          (""),
                         ])
def test_non_shortcut_path(lnk):
    assert shortcut_path(lnk) == None

# As this is a live test, there may have been a lnk test that was found, which no longer exists at the time of the test
# Unfortunately, this is one of the shortcommings of running tests after the fact, rather than live
# This returns None as the path does not exist
def test_non_existant_shortcut():
    lnk = r"C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\short_test.lnk"
    assert shortcut_path(lnk) == None

# All Test Passed
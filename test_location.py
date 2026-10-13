from prototype import location
import pytest

# These teste check the location function with different parameters

#First, testing for path input that it should either recognise at safe or suspicious
@pytest.mark.parametrize("paths, expected_location",
                         [("C:\\Program Files\\Microsoft OneDrive","safe"),
                          ("C:\\Program Files (x86)\\Microsoft", "safe"),
                          ("\\Temp","suspicious"),
                          ("C:\\Users\\vboxuser\\Downloads","suspicious"),
                          ("C:\\Users\\vboxuser\\Desktop\\Macros","suspicious"),               
                         ])
def test_loc(paths,expected_location):
    assert location(paths) == expected_location

# Then, checking with unrecognised conditions, such as non-path locations.
def test_non_path():
    path = "Not_A_Path_Test"
    assert location(path) == "unrecognised"
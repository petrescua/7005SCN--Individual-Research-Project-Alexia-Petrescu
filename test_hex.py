from prototype import hex_int
import pytest

# Checks if it turns the hex into an int value, but only if it is in the particular format required 
@pytest.mark.parametrize("hex, decimal",
                         [("0x0000",0),
                          ("0x0001",1),
                          ("0x0002",2),
                          ("0xff",255),
                          ("test",None),  
                          ("123",None),   
                         ])
def test_hex(hex, decimal):
    assert hex_int(hex) == decimal

# All tests passed
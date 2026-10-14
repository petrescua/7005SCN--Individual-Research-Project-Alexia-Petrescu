import pytest
import prototype

# This function checks if there is already a csv file with the name presented.
# If that is the case, it writes in the set all the event id it can find
# For all these tests the tmp_path will be used, to not create any extra paths

# Firstly, test the function with a non existent file
def test_no_file(tmp_path):
    no_file = tmp_path / "test.csv"
    assert prototype.check_log_id(str(no_file)) == set()

# Test checks the numbers are strings and not integers, as in the previous function they are turned into strings
def test_no_int(tmp_path):
    no_int = tmp_path / "test.csv"
    no_int.write_text("Event ID,Risk Level\n"
                              "0,High\n""1,Medium\n""2,High\n")
    ids = prototype.check_log_id(str(no_int))

    assert "2" in ids
    assert 100 not in ids


# Test checks the function with multiple event ID, if functions picks them up or not
def test_file(tmp_path):
    event_file = tmp_path / "test.csv"
    event_file.write_text("Event ID,Risk Level\n"
                          "0,High\n""1,Medium\n""2,High\n")
    
    assert prototype.check_log_id(str(event_file)) == {"0","1","2"}


# Test checks the function does not write the same number twice 
def test_duplicate(tmp_path):
    event_duplicate= tmp_path / "test.csv"
    event_duplicate.write_text("Event ID,Risk Level\n"
                          "0,High\n""0,Medium\n""2,High\n")
    
    assert prototype.check_log_id(str(event_duplicate)) == {"0","2"}

# Test checks the function returns nothing if only headers present.
def test_header(tmp_path):
    file_header = tmp_path / "test.csv"
    file_header.write_text("Event ID,Risk Level\n")
    
    assert prototype.check_log_id(str(file_header)) == set()

# All Test Passed
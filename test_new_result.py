import prototype

# This function checks if the result of the prototype testing is new or if it has already been logged.
# If it has already been logged, it does not log it again.
# For all these tests the tmp_path will be used, to not create any extra paths

# First test checks if the function captures the new result  
def test_result(tmp_path):
    output_result = [{"Event ID": "1", "Risk Level" : "High"}]

    log = set()
    output_file = tmp_path /"test.csv"
    field_name = ["Event ID","Risk Level"]

    result = prototype.new_results(output_result,log,output_file,field_name)
    assert len(result) == 1

# Test checks if the function only captures results that have not already been shown
def test_one_new_result(tmp_path):
    output_result = [{"Event ID": "1", "Risk Level" : "High"},
                     {"Event ID": "2", "Risk Level" : "Medium"},
                     {"Event ID": "3", "Risk Level" : "High"}]
    log = {"2"}
    output_file = tmp_path /"test.csv"
    field_name = ["Event ID","Risk Level"]

    result = prototype.new_results(output_result,log,output_file,field_name)
    assert len(result) == 2

# Test checks if the function returns back 0 when the result is empty
def test_empty_result(tmp_path):
    output_result = []
    log = set()
    output_file = tmp_path /"test.csv"
    field_name = ["Event ID","Risk Level"]

    result = prototype.new_results(output_result,log,output_file,field_name)
    assert len(result) == 0

# Test checks if function returns 0 when result is full, but already logged
def test_no_new_result(tmp_path):
    output_result = [{"Event ID": "1", "Risk Level" : "High"},
                     {"Event ID": "2", "Risk Level" : "Medium"},
                     {"Event ID": "3", "Risk Level" : "High"}]
    log = {"1","2","3"}
    output_file = tmp_path /"test.csv"
    field_name = ["Event ID","Risk Level"]

    result = prototype.new_results(output_result,log,output_file,field_name)
    assert len(result) == 0

# All Test Passed
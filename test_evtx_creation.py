import subprocess
from prototype import evtx_file, sys_log_channel, ps_log_channel
import pytest

log_file = "test.evtx"

# Testing if the function creates the evtx file correclty
# Testing without running a command in Windows, therefore monkeypatch required 
@pytest.fixture
def captured(monkeypatch):
    cmd_dict = {"error": None}
    
    def test_run(command, **kwargs):
        cmd_dict["command"] = command
        if cmd_dict["error"]:
            raise cmd_dict["error"]

    monkeypatch.setattr(subprocess, "run", test_run)
    return cmd_dict

# First, check the structure of the command is correctly set it by checking each area
@pytest.mark.parametrize("log_channel,event",
                         [(ps_log_channel, 4104),
                          (sys_log_channel, 1),
                          (sys_log_channel, 13),
                          (sys_log_channel, 11) 
                         ])
def test_correct_structure(captured,log_channel,event):

    evtx_file(log_channel,log_file,eventID=event)

    assert captured["command"][0] == "wevtutil"
    assert captured["command"][2] == "Microsoft-Windows-Sysmon/Operational" or captured["command"][2] == "Microsoft-Windows-PowerShell/Operational"
    assert captured["command"][3] == "test.evtx"
    assert captured["command"][4].startswith("/q:*[System[")
    assert f"EventID={event}" in captured["command"][4]

# Test checks if the hours into milliseconds handles different hour changes
def test_miliseconds(captured):
    evtx_file(sys_log_channel,log_file,hours=1,eventID=1)
    assert "<= 3600000" in captured["command"][4]

    evtx_file(sys_log_channel,log_file,hours=24,eventID=1)
    assert "<= 86400000" in captured["command"][4]

# Test checks if  file not found occurs, including what sys exit it produces and what it tells the user
def test_file_not_found(captured,capsys):
    captured["error"] = FileNotFoundError()

    with pytest.raises(SystemExit) as info:
        evtx_file(sys_log_channel,log_file,hours=1,eventID=1)

    assert info.value.code == 1
    assert "Error: File not found." in capsys.readouterr().out

# Checks how the function handles other error types
def test_exceptions(captured,capsys):
    captured["error"] = PermissionError()

    with pytest.raises(SystemExit) as info:
        evtx_file(sys_log_channel,log_file,hours=1,eventID=1)

    assert info.value.code == 1
    assert "Unexpected error:" in capsys.readouterr().out

# All Test Passed
import prototype
import pytest

# This function iterates through the evtx file created and checks if any new start up shortcuts of files have appeared in the Startup folder
# It then checks for the validity of the path, where it originates from, if it might be a suspisous base path, and other important information

# To check the function, the test bellow were created.
# fake_event creates a fake log taken from real data when a startup is made
# However, some areas of the log have been taken out for brevity and simplicity, they however do not affect the script in any way.

def fake_event(target,time,record="0"):
    return f'''- <Event xmlns=>
- <System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="" /> 
  <EventID>11</EventID> 
  <Version>2</Version> 
  <Level>4</Level> 
  <Task>11</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime="{time}" /> 
  <EventRecordID>{record}</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="3592" ThreadID="4528" /> 
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
  <Computer>DISWIN</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
- <EventData>
  <Data Name="RuleName">T1023</Data> 
  <Data Name="UtcTime">2026-10-13 13:33:18.089</Data> 
  <Data Name="ProcessId">6012</Data> 
  <Data Name="TargetFilename">{target}</Data> 
  <Data Name="CreationUtcTime">2026-10-13 13:33:03.242</Data> 
  </EventData>
  </Event> '''

# Creating the fake log, and monkeypatching it so it runs test version instead of real version
@pytest.fixture
def fake_log(monkeypatch):
    # XML strin goes through this list
    events = []

    # runs fake xml instead of real one
    class FakeRecord:
        def __init__(self, xml_text):
            self._xml = xml_text
        def xml(self):
            return self._xml
    # runs the fake version of evtx
    class  FakeEvtx:
        def __init__(self,path):
            pass
        def __enter__(self):
            return self
        # if it fails, shows why
        def __exit__(self, *args):
            return False
        def records(self):
            return[FakeRecord(e) for e in events]

    monkeypatch.setattr(prototype, "Evtx", FakeEvtx)
    monkeypatch.setattr(prototype, "evtx_file", lambda *args, **kwargs:None)
    return events

# First Testing that the results show up correctly with a known trigger
def test_start_up(fake_log):
    fake_log.append(fake_event(r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Test_powershell.lnk',
                               r'2026-10-13 13:33:18.0905216Z'))
    result = prototype.startup_reader()

    assert result[0]["Event ID"] == "0"
    assert result[0]["Timestamp (UTC)"] == "2026-10-13 13:33:18"
    assert result[0]["Path"] == r"C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Test_powershell.lnk"
    assert result[0]["Risk Level"] == "High"
    assert result[0]["Target"] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert result[0]["Type"] == "Shortcut"
    assert result[0]["Signature Status"] == "Valid"
    

# Test multiple log types and their different risk levels
@pytest.mark.parametrize("target, time, expected_risk",
                         [(r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Test_powershell.lnk',
                           r'2026-10-13 13:33:18.0905216Z',
                           "High"),
                           (r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\test.lnk',
                           r'2026-10-13 13:33:18.0905216Z',
                           "Medium"),
                          ])
def test_risk_score(fake_log,target,time,expected_risk):
    fake_log.append(fake_event(target,time))
    result = prototype.startup_reader()

    assert result[0]["Risk Level"] == expected_risk

# Test non suspicious code
def test_non_suspicious_code(fake_log):
    fake_log.append(fake_event(r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\~ew shortcut.tmp',
                                   time="",record="3"))
    assert prototype.startup_reader() == []

# Test multipe logs, some suspicious some not, script should only bring back suspicious one
def test_multiple(fake_log):
    fake_log.append(fake_event(r'',
                                time="",record="1"))
    fake_log.append(fake_event(r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Test_powershell.lnk',
                                time="",record="2"))
    fake_log.append(fake_event(r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\~ew shortcut.tmp',
                               time="",record="3"))
    
    result = prototype.startup_reader()

    assert len(result) == 1
    assert result[0]["Event ID"] == "2"
                                  

# Test empty log
def test_empty(fake_log):
    fake_log.append(fake_event("",""))
    assert prototype.startup_reader() == []

# Test no time and no event id
def test_no_time_no_id(fake_log):
    fake_log.append(fake_event(r'C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Test_powershell.lnk',
                                time="",record=""))

    assert prototype.startup_reader()[0]["Timestamp (UTC)"] == "unknown"
    assert prototype.startup_reader()[0]["Event ID"] == "unknown"   


# All tests have passed
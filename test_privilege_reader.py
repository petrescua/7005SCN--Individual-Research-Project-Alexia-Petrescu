import prototype
import pytest

# This function checks if the UAC controls have been altered from their normal state
# It checks what the number is, and what the number has been changed to

# To check the function, the test bellow were created.
# Fake_event creates a fake log taken from real data when a startup is made
# However, some areas of the log have been taken out for brevity and simplicity, they however do not affect the script in any way.

# Creating the fake event
def fake_event(image, target, details, time, record=0):
    return f'''Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="" /> 
  <EventID>13</EventID> 
  <Version>2</Version> 
  <Level>4</Level> 
  <Task>13</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime={time}/> 
  <EventRecordID>{record}</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="3592" ThreadID="4528" /> 
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
  <Computer>DISWIN</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
- <EventData>
  <Data Name="RuleName">-</Data> 
  <Data Name="EventType">SetValue</Data> 
  <Data Name="UtcTime">2026-10-13 10:28:53.473</Data> 
  <Data Name="ProcessId">3844</Data> 
  <Data Name="Image">{image}</Data> 
  <Data Name="TargetObject">{target}</Data> 
  <Data Name="Details">{details}</Data> 
  <Data Name="User"></Data> 
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

# Firstly, testing the results show up correctly by testing a known trigger
def test_variable(fake_log):
    fake_log.append(fake_event(image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                               target=r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
                               details='DWORD (0x00000000)',
                               time= '"2026-10-13 09:50:07.4742112Z"'))
    result = prototype.pr_reader()

    assert len(result) == 1
    assert result[0]["Event ID"] == "0"
    assert result[0]["Timestamp (UTC)"] == r"2026-10-13 09:50:07"
    assert result[0]["Category"] == "PromptOnSecureDesktop"
    assert result[0]["Risk Level"] == "High"
    assert result[0]["Expected Value"] == 1
    assert result[0]["Changed to"] == 0
    assert result[0]["Changed by"] == "powershell.exe"

# Tests all of the different rules with different values and different images that may have changed them
# This determines if the risk level is the expected one at the end.
@pytest.mark.parametrize("image, target, details, time, expected_risk",
                         [( r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
                            r'DWORD (0x00000002)',
                            r"2026-10-13 10:28:53.4742112Z",
                            "High"),
                         ( r'C:\Windows\System32\rundll32.exe',
                            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorEnhancedAdmin',
                            r'DWORD (0x00000000)',
                            r"2026-10-13 10:28:53.4742112Z",
                            "High"), 
                          ( r'C:\Windows\System32\cmd.exe',
                            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
                            r'DWORD (0x00000001)',
                            r"2026-10-13 10:28:53.4742112Z",
                            "High"), 
                          ( r'C:\Windows\System32\wscript.exe',
                            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
                            r'DWORD (0x00000002)',
                            r"2026-10-13 10:28:53.4742112Z",
                            "High"),   
                          ( r'C:\Windows\System32\test.exe',
                            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
                            r'DWORD (0x00000000)',
                            r"2026-10-13 10:28:53.4742112Z",
                            "Medium"),                        
                         ])
def test_risk_score(fake_log,image, target, details, time, expected_risk):
    fake_log.append(fake_event(image, target, details, time))

    result = prototype.pr_reader()

    assert result[0]["Risk Level"] == expected_risk

# Test checks for non suspicious, non value changing events
def test_non_suspicious(fake_log):
    fake_log.append(fake_event("",r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Prompt',"",""))
    assert prototype.pr_reader() == []

# Test checks for empty event log
def test_empty_log(fake_log):
    fake_log.append(fake_event("","","",""))
    assert prototype.pr_reader() == []

# Test checks for multliple events that only the suspicious ones get allocated
def test_multiple(fake_log):
    fake_log.append(fake_event(r'C:\Windows\System32\wscript.exe',
                            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
                            r'DWORD (0x00000002)',
                            r"2026-10-13 10:28:53.4742112Z",
                            record=1))
    fake_log.append(fake_event(r'C:\Windows\System32\wscript.exe',
                                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
                                r'', # No change
                                r"2026-10-13 10:28:53.4742112Z",
                                record=2))
    
    result = prototype.pr_reader()
    assert len(result) == 1
    assert result[0]["Event ID"] == "1"

# Test checks no time, no event id
def test_no_time(fake_log):
    fake_log.append(fake_event(r'C:\Windows\System32\wscript.exe',
                                r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
                                r'DWORD (0x00000002)',
                                time="",
                                record=""))
    assert prototype.pr_reader()[0]["Timestamp (UTC)"]  == "unknown"
    assert prototype.pr_reader()[0]["Event ID"] == "unknown"

# All Test Passed
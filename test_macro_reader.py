import prototype
import pytest

# This function takes event id 1, checks if any macros were run and reports back what the macro did
# It shows what office document did this, including the type and name, as well as the suspicious command that it may have ran
# This function looks through the rulebook for commands to check if they are safe or not

# To check the function, the test bellow were created.
# Fake_event creates a fake log taken from real data when a startup is made
# However, some areas of the log have been taken out for brevity and simplicity, they however do not affect the script in any way.

# Creating the fake event
def fake_event(parent,image,cmd,document,timestamp='"2026-10-12 11:08:29.1929631Z"',record="0"):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="" /> 
  <EventID>1</EventID> 
  <Version>5</Version> 
  <Level>4</Level> 
  <Task>1</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime={timestamp}>
  <EventRecordID>{record}</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="3840" ThreadID="4228" /> 
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
  <Computer>DISWIN</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
  <EventData>
  <Data Name="RuleName">-</Data> 
  <Data Name="UtcTime">2026-10-12 11:08:28.824</Data> 
  <Data Name="ProcessGuid"></Data> 
  <Data Name="ProcessId">9560</Data> 
  <Data Name="Image">{image}</Data> 
  <Data Name="FileVersion">10.0.26100.9278 (WinBuild.160101.0800)</Data> 
  <Data Name="Description">Windows PowerShell</Data> 
  <Data Name="Product">Microsoft® Windows® Operating System</Data> 
  <Data Name="Company">Microsoft Corporation</Data> 
  <Data Name="OriginalFileName">PowerShell.EXE</Data> 
  <Data Name="CommandLine">{cmd}</Data> 
  <Data Name="LogonGuid"></Data> 
  <Data Name="LogonId">0x7af1f</Data> 
  <Data Name="TerminalSessionId">1</Data> 
  <Data Name="IntegrityLevel">Medium</Data> 
  <Data Name="Hashes"></Data> 
  <Data Name="ParentProcessGuid"></Data> 
  <Data Name="ParentProcessId">7172</Data> 
  <Data Name="ParentImage">{parent}</Data> 
  <Data Name="ParentCommandLine">{document}</Data> 
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

# First, checking the all the variables gain the correct values by testing a known trigger
def test_macro(fake_log):
    fake_log.append(fake_event(parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                               image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                               cmd=r"powershell.exe -w hidden -enc & Base64EncodedTestCommand()",
                               document=r'"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\vboxuser\Desktop\office doc\Macro_setup.docx" /o ""',
                               ))
    result = prototype.macro_reader()

    assert len(result) == 1
    assert result[0]["Event ID"] == "0"
    assert result[0]["Timestamp (UTC)"] == "2026-10-12 11:08:29"
    assert result[0]["Category"] == "Office app WINWORD.EXE ran powershell.exe"
    assert result[0]["Risk Level"] == "High"
    assert result[0]["Command"] == "powershell.exe -w hidden -enc & Base64EncodedTestCommand()"
    assert result[0]["From Document"] == "Macro_setup.docx"

# Test checks multiple events, and test if the expected risk is the risk that is shown in the results section
@pytest.mark.parametrize("parent, image, cmd, document,expected_risk",
                         [(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                           r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                           "powershell.exe -w hidden -enc & Base64EncodedTestCommand()",
                           r'"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\vboxuser\Desktop\office doc\Macro_setup.docx" /o ""',
                           "High"),
                           (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                           r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                           "powershell.exe -w hidden ",
                           r'"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\vboxuser\Desktop\office doc\Macro_setup.docx" /o ""',
                           "Medium"),
                          ])
def test_risk_score(parent, image, cmd, document,expected_risk,fake_log):
    fake_log.append(fake_event(parent,image,cmd,document))
    result = prototype.macro_reader()

    assert result[0]['Risk Level'] == expected_risk

# Test checks if only suspicious events are getting attached to the result, even when there are multiple shown.
def tets_only_suspicious(fake_log):
    fake_log.append(fake_event(parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                                       image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                       cmd=r"powershell.exe -w hidden -enc & Base64EncodedTestCommand()",
                                       document=r'"C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\vboxuser\Desktop\office doc\Macro_setup.docx" /o ""',
                                       record="1"
                                       ))
    fake_log.append(fake_event(parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                                   image=r"C:\Program Files\Microsoft Office\root\Office16\ai.exe",
                                   cmd="n/a",
                                   document="n/a",
                                   record= "2"
                                   ))
   
    result = prototype.macro_reader()
    assert len(result) == 1
    assert result[0]["Event ID"] == "2"


# Test checks empty event, the result will not be shown
def test_non_suspicious(fake_log):
    fake_log.append(fake_event("","","",""))
    assert prototype.macro_reader() == []

# Test checks if unknown areas are shown as unknown
def test_unknown(fake_log):
    fake_log.append(fake_event(parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                               image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                               cmd="",
                               document="",
                               record="",
                               timestamp=""))
    result = prototype.macro_reader()
    assert result[0]["Event ID"] == "Unknown"
    assert result[0]["Timestamp (UTC)"] == "Unknown"
    assert result[0]["From Document"] == "Unknown"

# All Test Passed

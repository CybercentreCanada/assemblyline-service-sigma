import pytest
from assemblyline_service_utilities.common.balbuzard.patterns import PatternMatch
from sigma_.sigma import EventDataSection


class TestEventDataSection:
    @staticmethod
    @pytest.mark.parametrize("event, expected_tags",
        [
            ({
                'Event': {
                    'EventData': {
                        "CommandLine": "blah blah blah http://evil.com/bad blah blah"
                    },
                    'System': {
                        'Channel': 'Microsoft-Windows-Sysmon/Operational',
                        'EventID': 13,
                    }
                }
            }, {"network.dynamic.uri": ["http://evil.com/bad"]}),
            ({
                 'Event': {
                     'EventData': {
                         "ParentCommandLine": "ftp://good.com/justkidding blah blah http://evil.com/bad blah blah"
                     },
                     'System': {
                         'Channel': 'Microsoft-Windows-Sysmon/Operational',
                         'EventID': 13,
                     }
                 }
             }, {"network.dynamic.uri": ["ftp://good.com/justkidding", "http://evil.com/bad"]}),
            ({
                 'EventData': {
                     'Data': [{
                         "@Name": "CommandLine",
                         "#text": "ftp://good.com/justkidding blah blah http://evil.com/bad blah blah"
                     }]
                 },
                 'System': {
                     'Channel': 'Microsoft-Windows-Sysmon/Operational',
                     'EventID': 13,
                 }
             }, {"network.dynamic.uri": ["ftp://good.com/justkidding", "http://evil.com/bad"]}),
    ])
    def test_init(event, expected_tags):
        patterns = PatternMatch()
        actual_res_sec = EventDataSection(event, patterns.PAT_URI_NO_PROTOCOL)
        assert set(actual_res_sec.tags["network.dynamic.uri"]) == set(expected_tags["network.dynamic.uri"])

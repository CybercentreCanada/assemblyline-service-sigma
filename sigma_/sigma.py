from collections import defaultdict
import json
import tempfile
from typing import Dict

from assemblyline.common.str_utils import safe_str
from assemblyline.common.attack_map import attack_map
from assemblyline.odm.models.ontology.results import Process, Signature
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
# from assemblyline_v4_service.common.dynamic_service_helper import Process as DynamicProcess - Pending changes for tags
from pysigma.pysigma import PySigma
from pysigma.parser import get_category
from pkg_resources import get_distribution
from re import findall

SCORE_HEUR_MAPPING = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "null": 5,
    None: 5
}


def extract_from_events(event_json: Dict):
    system_data, event_data = None, None
    if 'Event' in event_json:
        # evtx log structured slightly different
        system_data = event_json['Event']['System']
        event_data = event_json['Event'].get('EventData', {})
    else:
        system_data = event_json['System']
        event_data = dict()
        for ordered_dict in event_json['EventData']['Data']:
            event_data[ordered_dict['@Name']] = ordered_dict.get('#text', None)
    return system_data, event_data


def get_signature_processes(event_body: Dict):
    source = {
        'objectid': {
            'guid': event_body.get('SourceProcessGUID'),
            'tag': event_body['SourceImage'].split('\\')[-1],
            'time_observed': event_body.get('UtcTime')

        },
        'pid': event_body.get('SourceProcessId'),
        'image': event_body.get('SourceImage'),
        'start_time': event_body.get('UtcTime'),
    }

    target = {
        'objectid': {
            'guid': event_body.get('TargetProcessGUID'),
            'tag': event_body['TargetImage'].split('\\')[-1],
            'time_observed': event_body.get('UtcTime')
        },
        'pid': event_body.get('TargetProcessId'),
        'image': event_body.get('TargetImage'),
        'start_time': event_body.get('UtcTime'),
    }

    source['objectid']['ontology_id'] = Process.get_oid(source)
    target['objectid']['ontology_id'] = Process.get_oid(target)

    return source, target


def get_process_ontology(event_body: Dict):
    data = {
        'objectid': {
            'guid': event_body.get('ProcessGuid'),
            'tag': event_body['Image'].split('\\')[-1],
            'time_observed': event_body.get('UtcTime')
        },
        'pimage': event_body.get('ParentImage'),
        'pcommand_line': event_body.get('ParentCommandLine'),
        'ppid': event_body.get('ParentProcessId'),
        'pid': event_body.get('ProcessId'),
        'image': event_body.get('Image'),
        'command_line': event_body.get('CommandLine'),
        'start_time': event_body.get('UtcTime'),
        'integrity_level': event_body.get('IntegrityLevel'),
        'original_file_name': event_body.get('OriginalFileName'),
    }

    data['objectid']['ontology_id'] = Process.get_oid(data)

    return data


class EventDataSection(ResultSection):
    def __init__(self, event_data: Dict, uri_pattern: bytes) -> None:
        title = "Event Data"
        system_fields, json_body = extract_from_events(event_data)
        json_body = json_body or dict()
        for k, v in system_fields.items():
            if k in ('Channel', 'EventID'):
                json_body[k] = v
        body = {k: v for k, v in json_body.items() if v}
        tags = defaultdict(list)
        commandline_keys = ["CommandLine", "ParentCommandLine"]
        if any(k in body for k in commandline_keys):
            for item in commandline_keys:
                v = body.get(item)
                if v:
                    uris = set(findall(uri_pattern, v.encode()))
                    if uris:
                        tags["network.dynamic.uri"].extend([safe_str(uri).strip(",'") for uri in uris])
        super(EventDataSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(body),
            tags=tags
        )


class SigmaHitSection(ResultSection):
    def __init__(self, title: str, events: Dict) -> None:
        score = events[0]['score']
        json_body = dict(
            yaml_score=score
        )
        super(SigmaHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body),
            auto_collapse=True
        )


class Sigma(ServiceBase):
    def __init__(self, config: Dict = None) -> None:
        super(Sigma, self).__init__(config)
        self.sigma_parser = PySigma()
        self.sigma_parser.hits = {}
        self.patterns = PatternMatch()

    def _load_rules(self) -> None:
        temp_list = []
        # Patch source_name into signature and import
        for rule in self.rules_list:
            with open(rule, 'r') as yaml_fh:
                file = yaml_fh.read()
                source_name = rule.split('/')[-2]
                patched_rule = f'{file}\nsignature_source: {source_name}'
                temp_list.append(patched_rule)

        self.log.info(f"Number of rules to be loaded: {len(temp_list)}")
        for rule in temp_list:
            try:
                self.sigma_parser.add_signature(rule)
            except Exception as e:
                self.log.warning(f"{e} | {rule}")

        self.log.info(f"Number of rules successfully loaded: {len(self.sigma_parser.rules)}")

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        self.sigma_parser.hits = {}  # clear the hits dict
        path = request.file_path
        file_name = request.file_name
        self.log.info(f" Executing {file_name}")

        with tempfile.NamedTemporaryFile('w+', delete=False) as event_dump:
            for line in self.sigma_parser.check_logfile(path):
                event_dump.write(f"{json.dumps(line)}\n")
            event_dump.seek(0)
            request.add_supplementary(event_dump.name, f"{file_name}_event_dump", "Output from Sigma Parser")

        if len(self.sigma_parser.hits) > 0:
            hit_section = ResultSection('Events detected as suspicious')
            # group alerts together
            for id, events in self.sigma_parser.hits.items():
                title = self.sigma_parser.rules[id].title
                section = SigmaHitSection(title, events)
                tags = self.sigma_parser.rules[id].tags
                attack_id = None
                if tags:
                    for tag in tags:
                        name = tag[7:]
                        if name.startswith(('t', 'g', 's')):
                            attack_id = name.upper()
                source = events[0]['signature_source']
                score = events[0].get('score', None)
                sig = f"{source}.{title}"
                heur_id = SCORE_HEUR_MAPPING.get(score, None)
                if heur_id:
                    section.set_heuristic(heur_id, attack_id=attack_id, signature=sig)
                else:
                    self.log.warning(f"Sigma rule {sig} has an invalid threat level: {score}")
                section.add_tag("file.rule.sigma", sig)

                attributes = []
                attributes_record = []
                for event in events:
                    sys, json_body = extract_from_events(event)
                    attribute = None
                    attr_key = None
                    if 'CallTrace' in str(event):
                        s_proc, t_proc = get_signature_processes(json_body)
                        attr_key = f"{s_proc['objectid']['ontology_id']}:{t_proc['objectid']['ontology_id']}"
                        attribute = dict(
                            event_record_id=sys.get('EventRecordID'),
                            source=s_proc['objectid'],
                            target=t_proc['objectid'],
                            action=get_category(sys))
                    elif json_body and json_body.get('ProcessGuid'):
                        proc = get_process_ontology(json_body)
                        attr_key = proc['objectid']['ontology_id']
                        attribute = dict(event_record_id=sys.get('EventRecordID'),
                                         source=proc['objectid'])
                    if attr_key and attr_key not in attributes_record:
                        attributes.append(attribute)
                        attributes_record.append(attr_key)

                    # add the event data as a subsection
                    section.add_subsection(EventDataSection(event, self.patterns.PAT_URI_NO_PROTOCOL))
                hit_section.add_subsection(section)
                s_ont = dict(name=sig, type='SIGMA', attributes=attributes)
                if attack_id and attack_map.get('attack_id'):
                    attack = attack_map[attack_id]
                    s_ont['attacks'] = [
                        {'attack_id': attack_id, 'pattern': attack['name'],
                         'categories': attack['categories']}]
                self.ontology.add_result_part(Signature, data=s_ont)
            result.add_section(hit_section)
        request.result = result

    def get_tool_version(self):
        """
        Return the version of Pysigma used for processing
        :return:
        """
        version_string = get_distribution("pysigma").version
        return f'{version_string}.r{self.rules_hash}'

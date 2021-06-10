import json
import os

from typing import Dict, List, Any, Optional

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

from pysigma import pysigma

FILE_UPDATE_DIRECTORY = os.environ.get('FILE_UPDATE_DIRECTORY', "/tmp/sigma_updater_output/sigma")


def get_rules(self) -> Optional[List[str]]:
    sigma_rules_path = FILE_UPDATE_DIRECTORY
    source = self.service_attributes.update_config.sources
    signature_sources = [s['name'] for s in source]
    split_rules = []

    if not os.path.exists(sigma_rules_path):
        self.log.error("Sigma rules directory not found")
        return None
    if sigma_rules_path.startswith('/mount'):
        # Running in Container
        try:
            rules_directory = max([os.path.join(sigma_rules_path, d) for d in os.listdir(sigma_rules_path)
                                   if os.path.isdir(os.path.join(sigma_rules_path, d)) and not
                                   d.startswith(".tmp")], key=os.path.getctime)
        except ValueError:
            self.log.error("Sigma rules directory not found")
            return None
        sigma_rules_path = os.path.join(rules_directory, 'sigma')
    for signature in signature_sources:
        with open(os.path.join(sigma_rules_path, signature)) as yaml_fh:
            file = yaml_fh.read()
            rules = file.split('\n\n\n')
            for rule in rules:
                rule = rule + f'\nsignature_source: {signature}'
                split_rules.append(rule)
    self.log.info(f"Loaded {len(split_rules)} rules")
    return split_rules


class EventDataSection(ResultSection):
    def __init__(self, event_data: Dict) -> None:
        title = "Event Data"
        json_body = {}
        if 'Event' in event_data:
            # evtx log structured slightly different
            system_fields = event_data['Event']['System']
            json_body = event_data['Event']['EventData']
        else:
            system_fields = event_data['System']
            for ordered_dict in event_data['EventData']['Data']:
                json_body[ordered_dict['@Name']] = ordered_dict.get('#text', None)

        for k, v in system_fields.items():
            if k in ('Channel', 'EventID'):
                json_body[k] = v
        body = {k: v for k, v in json_body.items() if v}
        super(EventDataSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(body)
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
            body=json.dumps(json_body)
        )


def get_heur_id(level: str) -> int:
    if level == "critical":
        return 1
    elif level == "high":
        return 2
    elif level == "medium":
        return 3
    elif level == "low":
        return 4
    else:
        return 0


class Sigma(ServiceBase):
    def __init__(self, config: Dict = None) -> None:
        super(Sigma, self).__init__(config)
        self.sigma_parser = pysigma.PySigma()
        self.hits = {}
        rules = get_rules(self)
        for rule in rules:
            try:
                self.sigma_parser.add_signature(rule)
            except Exception as e:
                self.log.warning(e)

    def sigma_hit(self, alert: Dict, event: Dict) -> None:
        id = alert['id']
        if id not in self.hits:
            event['score'] = alert['score']
            event['signature_source'] = alert['signature_source']
            self.hits[id] = [event]
        else:
            self.hits[id].append(event)

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        self.hits = {}  # clear the hits dict
        path = request.file_path
        file_name = request.file_name
        self.log.info(f" Executing {file_name}")
        self.log.info(f"Number of rules {len(self.sigma_parser.rules)}")
        self.sigma_parser.register_callback(self.sigma_hit)
        self.sigma_parser.check_logfile(path)
        if len(self.hits) > 0:
            hit_section = ResultSection('Events detected as suspicious')
            # group alerts together
            for id, events in self.hits.items():
                title = self.sigma_parser.rules[id].title
                section = SigmaHitSection(title, events)
                tags = self.sigma_parser.rules[id].tags
                for tag in tags:
                    name = tag[7:]
                    if name.startswith(('t', 'g', 's')):
                        attack_id = name.upper()
                source = events[0]['signature_source']
                if attack_id:
                    section.set_heuristic(get_heur_id(events[0]['score']), attack_id=attack_id,
                                          signature=f"{source}.{title}")
                    section.add_tag(f"file.rule.{source}", f"{source}.{title}")
                else:
                    section.set_heuristic(get_heur_id(events[0]['score']), signature=f"{source}.{title}")
                    section.add_tag(f"file.rule.{source}", f"{source}.{title}")
                for event in events:
                    # add the event data as a subsection
                    section.add_subsection(EventDataSection(event))
                hit_section.add_subsection(section)
            result.add_section(hit_section)
        request.result = result

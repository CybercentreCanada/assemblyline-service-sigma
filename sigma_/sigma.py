import copy
import json
from typing import Dict

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from pysigma.pysigma import PySigma

SCORE_HEUR_MAPPING = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4
}


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


class Sigma(ServiceBase):
    def __init__(self, config: Dict = None) -> None:
        super(Sigma, self).__init__(config)
        self.sigma_parser = PySigma()
        self.hits = {}

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

    def sigma_hit(self, alert: Dict, event: Dict) -> None:
        id = alert['id']
        copied_event = copy.deepcopy(event)
        if id not in self.hits:
            copied_event['score'] = alert['score']
            copied_event['signature_source'] = alert['signature_source']
            self.hits[id] = [copied_event]
        else:
            self.hits[id].append(copied_event)

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        self.hits = {}  # clear the hits dict
        path = request.file_path
        file_name = request.file_name
        self.log.info(f" Executing {file_name}")
        self.sigma_parser.register_callback(self.sigma_hit)
        self.sigma_parser.check_logfile(path)
        if len(self.hits) > 0:
            hit_section = ResultSection('Events detected as suspicious')
            # group alerts together
            for id, events in self.hits.items():
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
                heur_id = SCORE_HEUR_MAPPING.get(events[0]['score'], None)
                if heur_id:
                    section.set_heuristic(heur_id, attack_id=attack_id, signature=f"{source}.{title}")
                else:
                    self.log.warning(f"Unknown score-heuristic mapping for: {events[0]['score']}")
                section.add_tag("file.rule.sigma", f"{source}.{title}")

                for event in events:
                    # add the event data as a subsection
                    section.add_subsection(EventDataSection(event))
                hit_section.add_subsection(section)
            result.add_section(hit_section)
        request.result = result

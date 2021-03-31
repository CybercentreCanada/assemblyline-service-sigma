import json
import os
import xmltodict
from typing import Dict, Any

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

from pysigma import pysigma
from pysigma import exceptions
FILE_UPDATE_DIRECTORY = os.environ.get('FILE_UPDATE_DIRECTORY', "/tmp/sigma_updater_output/sigma")


def get_rules(self):
    sigma_rules_path = FILE_UPDATE_DIRECTORY
    if not os.path.exists(sigma_rules_path):
        self.log.error("Sigma rules directory not found")
        return None
    if sigma_rules_path.startswith('/mount'):
        # Running in Container
        try:
            rules_directory = max([os.path.join(sigma_rules_path, d) for d in os.listdir(sigma_rules_path)
                               if os.path.isdir(os.path.join(sigma_rules_path,d)) and not
                               d.startswith(".tmp")], key = os.path.getctime)
        except ValueError:
            self.log.error("Sigma rules directory not found")
            return None
        # rules_list = [str(f) for f in Path(rules_directory).rglob("*") if os.path.isfile(str(f))]
        # if len(rules_list) > 1:
        #     self.log.warning("Only one file should be in update directory")
        #     return None
        # self.log.info(f"rules list {rules_list}")
        sigma_rules_path = os.path.join(rules_directory,'sigma')

    self.log.info(sigma_rules_path)
    with open(os.path.join(sigma_rules_path, 'sigma')) as yaml_fh:
        file = yaml_fh.read()
        splitted_rules = file.split('\n\n\n')
    self.log.info(f"Loaded {len(splitted_rules)} rules")
    return splitted_rules


class EventDataSection(ResultSection):
    def __init__(self, event_data):
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

        for k,v in system_fields.items():
            if k in ('Channel', 'EventID'):
                json_body[k] = v
        body = {k:v for k,v in json_body.items() if v}
        super(EventDataSection, self).__init__(
            title_text = title,
            body_format = BODY_FORMAT.KEY_VALUE,
            body = json.dumps(body)
        )


class SigmaHitSection(ResultSection):
    def __init__(self, title, events):
        sc = events[0]
        score = sc['score']
        json_body = dict(
            yaml_score = score
        )
        super(SigmaHitSection, self).__init__(
            title_text = title,
            body_format = BODY_FORMAT.KEY_VALUE,
            body = json.dumps(json_body)
        )


def get_heur_id(level):
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
    def __init__(self, config = None):
        super(Sigma, self).__init__(config)
        self.sigma_parser = pysigma.PySigma()
        self.hits = {}
        rules = get_rules(self)
        for rule in rules:
            try:
                self.sigma_parser.add_signature(rule)
            except exceptions.UnsupportedFeature as e:
                self.log.warning(e)


    def sigma_hit(self, alert, event):
        title = alert['title']
        if title not in self.hits:
            event['score'] = alert['score']
            self.hits[title] = [event]
        else:
            self.hits[title].append(event)


    def execute(self, request: ServiceRequest) -> Dict[str, Any]:
        result = Result()
        self.hits = {}  # clear the hits dict
        path = request.file_path
        file_name = request.file_name
        source = self.service_attributes.update_config.sources
        sources = [s['name'] for s in source]
        self.log.info(f" Executing {file_name}")
        #self.log.info(f"Loaded {self.sigma_parser.rules}")
        self.log.info(f"number of rules {len(self.sigma_parser.rules)}")
        if file_name:
            self.sigma_parser.register_callback(self.sigma_hit)
            self.sigma_parser.check_logfile(path)
            if len(self.hits) > 0:
                hit_section = ResultSection('Events detected as suspicious')
                #group alerts together
                for title, events in self.hits.items():
                    section = SigmaHitSection(title, events)
                    tags = self.sigma_parser.rules[title].tags

                    for tag in tags:
                        name = tag[7:]
                        if name.startswith(('t','g','s')):
                            attack_id = name.upper()

                    if attack_id:
                        section.set_heuristic(get_heur_id(events[0]['score']), attack_id=attack_id, signature =f"{sources[0]}.{title}")
                        section.add_tag(f"file.rule.{sources[0]}", f"{sources[0]}.{title}")
                    else:
                        section.set_heuristic(get_heur_id(events[0]['score']), signature=f"{sources[0]}.{title}")
                        section.add_tag(f"file.rule.{sources[0]}", f"{sources[0]}.{title}")
                    self.log.info(tags)
                    for event in events:
                        #add the event data as a subsection
                        section.add_subsection(EventDataSection(event))
                    hit_section.add_subsection(section)
                result.add_section(hit_section)
            request.result = result
        else:
            self.log.info(f" {file_name} is not an EVTX file")
            request.result = result


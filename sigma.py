import json
import os
from typing import Dict, Any
from pathlib import Path

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
from sigma_signature import pysigma

FILE_UPDATE_DIRECTORY = os.environ.get('FILE_UPDATE_DIRECTORY', "/tmp/sigma_updater_output/sigma")


def get_rules(self):
    SIGMA_RULES_PATH = FILE_UPDATE_DIRECTORY

    if not os.path.exists(SIGMA_RULES_PATH):
        self.log.error("Sigma rules directory not found")
        return None
    if SIGMA_RULES_PATH.startswith('/mount'):
        # Running in Container
        try:
            rules_directory = max([os.path.join(SIGMA_RULES_PATH, d) for d in os.listdir(SIGMA_RULES_PATH)
                               if os.path.isdir(os.path.join(SIGMA_RULES_PATH,d)) and not
                               d.startswith(".tmp")], key = os.path.getctime)

        except ValueError:
            self.log.warning("Sigma rules directory not found")
            return None
        self.log.info(f"rules dir {rules_directory}")
        rules_list = [str(f) for f in Path(rules_directory).rglob("*") if os.path.isfile(str(f))]
        if len(rules_list) > 1:
            self.log.warning("Only one file should be in update directory")
            return None
        self.log.info(f"rules list {rules_list}")
        SIGMA_RULES_PATH = os.path.join(rules_directory,'sigma')

    self.log.info((SIGMA_RULES_PATH))
    with open(os.path.join(SIGMA_RULES_PATH, 'sigma')) as yaml_fh:
        file = yaml_fh.read()
        splitted_rules = file.split('\n\n\n')
    self.log.info(splitted_rules)
    self.log.info(f"Loaded {len(splitted_rules)} rules")
    return splitted_rules


class EventDataSection(ResultSection):
    def __init__(self, event_data):
        title = "Event Data"
        json_body = event_data['Event']['EventData']
        super(EventDataSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body)
        )


class SigmaHitSection(ResultSection):
    def __init__(self, alert, event):
        title = "Sigma match " + alert['yaml_name']
        json_body = dict(
            rule_name=alert['yaml_name'],
            yaml_score=alert['score']
        )
        super(SigmaHitSection, self).__init__(
            title_text=title,
            body_format=BODY_FORMAT.KEY_VALUE,
            body=json.dumps(json_body)
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
    sigma_parser = pysigma.PySigma()
    hits = []

    def __init__(self, config=None):
        super(Sigma, self).__init__(config)
        rules = get_rules(self)
        for rule in rules:
            self.sigma_parser.add_signature(rule)

    def sigma_hit(self, alert, event):
        self.hits.append((alert, event))


    def execute(self, request: ServiceRequest) -> Dict[str, Any]:
        result = Result()
        self.hits = []  # clear the hits list
        path = request.file_path
        file_name = request.file_name
        self.log.info(f" executing {file_name}")
        self.log.info(f"Loaded {self.sigma_parser.rules}")
        if file_name.endswith('evtx'):
            self.sigma_parser.register_callback(self.sigma_hit)
            # TODO cProfile.runctx('self.sigma_parser.check_logfile(path)', globals(), locals(),)
            self.sigma_parser.check_logfile(path)
            self.log.info("in evtx")
            if len(self.hits) > 0:
                hit_section = ResultSection('Events detected as suspicious')
                for alert, event in self.hits:
                    section = SigmaHitSection(alert, event)
                    section.set_heuristic(get_heur_id(alert['score']))
                    #add the event data as a subsection
                    section.add_subsection(EventDataSection((event)))
                    hit_section.add_subsection(section)
                result.add_section(hit_section)
            request.result = result
        else:
            self.log.info(f" {file_name} is not an EVTX file")
            request.result = result


import json
import os
from typing import Dict, Any
import yaml


from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
from sigma_signature import pysigma

UPDATE_OUTPUT_PATH = os.environ.get('UPDATE_OUTPUT_PATH', "/tmp/sigma_updater_output")


def get_filenames():
    filenames = []
    with open(os.path.join(UPDATE_OUTPUT_PATH, 'response.yaml')) as yaml_fh:
        yaml_data = yaml.safe_load(yaml_fh)
        json_data = json.loads(yaml_data['hash'])
        for source, data in json_data.items():
            for filename in data.keys():
                filenames.append(filename)
    return filenames

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
            yaml_name=alert['yaml_name'],
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
        filenames = get_filenames()
        for fn in filenames:
            with open(fn) as f:
                self.sigma_parser.add_signature(f)

    def sigma_hit(self, alert, event):
        self.hits.append((alert, event))


    def execute(self, request: ServiceRequest) -> Dict[str, Any]:
        result = Result()
        self.hits = []  # clear the hits list
        path = request.file_path
        file_name = request.file_name
        if file_name.endswith('evtx'):
            self.sigma_parser.register_callback(self.sigma_hit)
            # TODO cProfile.runctx('self.sigma_parser.check_logfile(path)', globals(), locals(),)
            self.sigma_parser.check_logfile(path)

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
            self.log.info(f"{file_name} is not an EVTX file")


import copy
import hashlib
import json
import requests
import os
import time
import tempfile
import tarfile
import shutil
from pathlib import Path
from typing import Dict

from assemblyline.common.digests import get_sha256_for_file
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from pysigma.pysigma import PySigma

UPDATES_HOST = os.environ.get('updates_host')
UPDATES_PORT = os.environ.get('updates_port')
UPDATES_KEY = os.environ.get('updates_key')

SCORE_HEUR_MAPPING = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4
}


# def get_rules(self) -> Optional[List[str]]:
#     sigma_rules_path = FILE_UPDATE_DIRECTORY
#     source = self.service_attributes.update_config.sources
#     signature_sources = [s['name'] for s in source]
#     split_rules = []

#     if not os.path.exists(sigma_rules_path):
#         self.log.error("Sigma rules directory not found")
#         return None
#     if sigma_rules_path.startswith('/mount'):
#         # Running in Container
#         try:
#             rules_directory = max([os.path.join(sigma_rules_path, d) for d in os.listdir(sigma_rules_path)
#                                    if os.path.isdir(os.path.join(sigma_rules_path, d)) and not
#                                    d.startswith(".tmp")], key=os.path.getctime)
#         except ValueError:
#             self.log.error("Sigma rules directory not found")
#             return None
#         sigma_rules_path = os.path.join(rules_directory, 'sigma')
#     for signature in signature_sources:
#         with open(os.path.join(sigma_rules_path, signature)) as yaml_fh:
#             file = yaml_fh.read()
#             rules = file.split('\n\n\n')
#             for rule in rules:
#                 rule = rule + f'\nsignature_source: {signature}'
#                 split_rules.append(rule)
#     self.log.info(f"Loaded {len(split_rules)} rules")
#     return split_rules


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

        # Updater-related
        self.rules_directory = None
        self.rules_list = []
        self.update_time = None
        self.rules_hash = ''

    def _get_rules_hash(self):
        self.rules_list = [str(f) for f in Path(self.rules_directory).rglob("*") if os.path.isfile(str(f))]
        all_sha256s = [get_sha256_for_file(f) for f in self.rules_list]

        self.log.info(f"Sigma will load the following rule files: {self.rules_list}")

        # Signature importer doesn't suppose loading rules en masse
        temp_list = []
        signature_sources = [s['name'] for s in self.service_attributes.update_config.sources]
        for signature in signature_sources:
            for sigma_rule_path in self.rules_list:
                if signature in sigma_rule_path:
                    with open(sigma_rule_path) as yaml_fh:
                        file = yaml_fh.read()
                        rules = file.split('\n\n\n')
                        for rule in rules:
                            rule = rule + f'\nsignature_source: {signature}'
                            temp_list.append(rule)
                    break
        self.rules_list = temp_list

        if len(all_sha256s) == 1:
            return all_sha256s[0][:7]

        return hashlib.sha256(' '.join(sorted(all_sha256s)).encode('utf-8')).hexdigest()[:7]

    def _download_rules(self):
        url_base = f'http://{UPDATES_HOST}:{UPDATES_PORT}/'
        headers = {
            'X_APIKEY': UPDATES_KEY
        }

        # Check if there are new
        while True:
            resp = requests.get(url_base + 'status')
            resp.raise_for_status()
            status = resp.json()
            if self.update_time is not None and self.update_time >= status['local_update_time']:
                return False
            if status['download_available']:
                break
            self.log.warning('Waiting on update server availability...')
            time.sleep(10)

        # Download the current update
        temp_directory = tempfile.mkdtemp()
        buffer_handle, buffer_name = tempfile.mkstemp()
        try:
            with os.fdopen(buffer_handle, 'wb') as buffer:
                resp = requests.get(url_base + 'tar', headers=headers)
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=1024):
                    buffer.write(chunk)

            tar_handle = tarfile.open(buffer_name)
            tar_handle.extractall(temp_directory)
            self.update_time = status['local_update_time']
            self.rules_directory, temp_directory = temp_directory, self.rules_directory
            return True
        finally:
            os.unlink(buffer_name)
            if temp_directory is not None:
                shutil.rmtree(temp_directory, ignore_errors=True)

    def _update_rules(self):
        if self._download_rules():
            self.rules_hash = self._get_rules_hash()

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
                section.add_tag(f"file.rule.{source}", f"{source}.{title}")

                for event in events:
                    # add the event data as a subsection
                    section.add_subsection(EventDataSection(event))
                hit_section.add_subsection(section)
            result.add_section(hit_section)
        request.result = result

    def start(self):
        try:
            # Load the rules
            self._update_rules()
        except Exception as e:
            raise Exception(f"Something went wrong while trying to load Sigma rules: {str(e)}")

        rules = self.rules_list
        for rule in rules:
            try:
                self.sigma_parser.add_signature(rule)
            except Exception as e:
                self.log.warning(f"{e} | {rule}")

    def _cleanup(self) -> None:
        super()._cleanup()
        try:
            self._update_rules()
        except Exception as e:
            raise Exception(f"Something went wrong while trying to load Sigma rules: {str(e)}")

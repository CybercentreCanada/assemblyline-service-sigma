import logging
import os
from typing import List
import yaml

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from sigma_signature import pysigma

ps = pysigma.PySigma()

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)


class SigmaImporter:
    def __init__(self, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('suricata_importer')
            logger = logging.getLogger('assemblyline.suricata_importer')
            logger.setLevel(logging.INFO)

        self.update_client = al_client

        self.classification = forge.get_classification()
        self.log = logger

    def _save_signatures(self, signature, source, cur_file, default_classification=None):
        signature_string = signature.readlines()
        signature_yaml = yaml.safe_load(signature_string)

        order = 1
        upload_list = []
        name = signature_yaml.get('id', None)
        status = "DEPLOYED"


        sig = Signature(dict(
            classification=default_classification or self.classification.UNRESTRICTED,
            data=signature_string,
            name=signature_yaml.get('title', None),
            order=order,
            signature_id=name,
            source=source,
            status=status,
            type="sigma",
        ))

        upload_list.append(sig.as_primitives())
        order += 1

        r = self.update_client.signature.add_update_many(source, 'suricata', upload_list, dedup_name=False)
        self.log.info(f"Imported {r['success']}/{order - 1} signatures"
                      f" from {os.path.basename(cur_file)} into Assemblyline")

        return r['success']

    def import_file(self, file_path: str, source: str, default_classification: str = None):
        self.log.info(f"Importing file: {file_path}")
        cur_file = os.path.expanduser(file_path)
        if os.path.exists(cur_file):
            try:
                with open(file_path) as f:
                    ps.add_signature(f)
                    return self._save_signatures(f, source, cur_file,
                                                 default_classification=default_classification)
            except:
                pass #TODO: complain that sigma_signature won't take that file


        else:
            raise Exception(f"File {cur_file} does not exists.")

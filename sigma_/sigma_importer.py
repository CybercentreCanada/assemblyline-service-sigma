import logging
import os
import yaml
from typing import List

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature

UPDATE_CONFIGURATION_PATH = os.environ.get('UPDATE_CONFIGURATION_PATH', None)
BATCH_SIZE_LIMIT = int(os.environ.get('SIG_BATCH_SIZE', 1000))


class SigmaImporter:
    def __init__(self, al_client, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('sigma_importer')
            logger = logging.getLogger('assemblyline.sigma_importer')
            logger.setLevel(logging.INFO)

        self.update_client = al_client

        self.classification = forge.get_classification()
        self.log = logger

    def _save_signatures(self, files: List[str], source: str, default_classification: str = None):
        upload_list = []
        order = 1
        order_completed = 0
        add_update_many = self.update_client.signature.add_update_many
        for file in files:
            signature_string = open(file, 'r').read()
            signature_yaml = yaml.safe_load(signature_string)
            name = signature_yaml.get('id', None)
            status = signature_yaml.get('status', 'DEPLOYED')
            if status in ['test', 'experimental']:
                status = 'NOISY'
            elif status in ['deprecated', 'unsupported']:
                status = "DISABLED"
            else:
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

            # If we hit the batch size limit, send to API
            if order % BATCH_SIZE_LIMIT == 0:
                self.log.info(f'Batch limit reached: {BATCH_SIZE_LIMIT}. Sending batch to Signature API..')
                order_completed += add_update_many(source, 'sigma', upload_list, dedup_name=False)['success']
                upload_list = []

        order_completed += add_update_many(source, 'sigma', upload_list, dedup_name=False)['success']
        self.log.info(f"Imported {order_completed}/{order - 1} signatures from {source} into Assemblyline")

        return order_completed

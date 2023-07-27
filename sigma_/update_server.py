import yaml

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline_v4_service.updater.updater import ServiceUpdater
from pysigma.exceptions import UnsupportedFeature
from pysigma.pysigma import val_file

classification = forge.get_classification()


class SigmaUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source, default_classification=classification.UNRESTRICTED):
        upload_list = []
        for file, _ in files_sha256:
            with open(file, 'r') as fh:
                signature_string = fh.read()
            signature_yaml = yaml.safe_load(signature_string)
            s_id = signature_yaml['id']
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
                name=signature_yaml.get('title', s_id),
                signature_id=s_id,
                source=source,
                status=status,
                type="sigma",
            ))

            upload_list.append(sig.as_primitives())

        order_completed = client.signature.add_update_many(source, 'sigma', upload_list, dedup_name=False)['success']
        self.log.info(f"Imported {order_completed} signatures from {source} into Assemblyline")

        return order_completed

    def is_valid(self, file_path) -> bool:
        try:
            return val_file(file_path)
        except UnsupportedFeature:
            return False


if __name__ == '__main__':
    with SigmaUpdateServer(default_pattern="*.yml") as server:
        server.serve_forever()

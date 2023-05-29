from assemblyline.common import forge
from assemblyline_v4_service.updater.updater import ServiceUpdater
from pysigma.exceptions import UnsupportedFeature
from pysigma.pysigma import val_file
from sigma_.sigma_importer import SigmaImporter

classification = forge.get_classification()


class SigmaUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source, default_classification=classification.UNRESTRICTED):
        sigma_importer = SigmaImporter(client, logger=self.log)
        files_to_import = [file for file, _ in files_sha256 if self.is_valid(file)]
        sigma_importer._save_signatures(files_to_import, source, default_classification)

    def is_valid(self, file_path) -> bool:
        try:
            return val_file(file_path)
        except UnsupportedFeature:
            return False


if __name__ == '__main__':
    with SigmaUpdateServer(default_pattern="*.yml") as server:
        server.serve_forever()

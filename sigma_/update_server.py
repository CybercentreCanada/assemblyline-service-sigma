from yaml.composer import ComposerError

from assemblyline.common import forge
from assemblyline_v4_service.updater.updater import ServiceUpdater

from sigma_.sigma_importer import SigmaImporter
from pysigma.pysigma import val_file
from pysigma.exceptions import UnsupportedFeature

classification = forge.get_classification()


class SigmaUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(self, files_sha256, client, source, default_classification=classification.UNRESTRICTED):
        sigma_importer = SigmaImporter(client, logger=self.log)
        total_imported = 0
        for file, _ in files_sha256:
            try:
                total_imported += sigma_importer.import_file(file, source, default_classification)
            except ValueError:
                self.log.warning(f"{file} failed to import due to a Sigma error")
            except ComposerError:
                self.log.warning(f"{file} failed to import due to a YAML-parsing error")
            except UnsupportedFeature as e:
                pass

        self.log.info(f"{total_imported} signatures were imported for source {source}")

    def is_valid(self, file_path) -> bool:
        try:
            return val_file(file_path)
        except UnsupportedFeature:
            return False


if __name__ == '__main__':
    with SigmaUpdateServer(default_pattern="*.yml") as server:
        server.serve_forever()

import logging
import os
import tempfile
import time

from yaml.composer import ComposerError

from assemblyline_client import get_client
from assemblyline.common import log as al_log, forge
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline_v4_service.updater.updater import ServiceUpdater, temporary_api_key
from assemblyline_v4_service.updater.helper import SkipSource, url_download, git_clone_repo

from sigma_.sigma_importer import SigmaImporter
from pysigma.pysigma import val_file
from pysigma.exceptions import UnsupportedFeature

al_log.init_logging('updater.sigma')
classification = forge.get_classification()

UPDATE_DIR = os.path.join(tempfile.gettempdir(), 'sigma_updates')
LOGGER = logging.getLogger('assemblyline.updater.sigma')

UI_SERVER = os.getenv('UI_SERVER', 'https://nginx')


class SigmaUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.updater_type = "sigma"

    def do_source_update(self, service: Service) -> None:
        self.log.info(f"Connecting to Assemblyline API: {UI_SERVER}...")
        run_time = time.time()
        username = self.ensure_service_account()
        with temporary_api_key(self.datastore, username) as api_key:
            al_client = get_client(UI_SERVER, apikey=(username, api_key), verify=False)
            old_update_time = self.get_source_update_time()

            self.log.info("Connected!")

            # Parse updater configuration
            previous_hashes: dict[str, str] = self.get_source_extra()
            sources: dict[str, UpdateSource] = {_s['name']: _s for _s in service.update_config.sources}
            files_sha256: dict[str, str] = {}
            source_default_classification = {}

            # Go through each source and download file
            for source_name, source_obj in sources.items():
                source = source_obj.as_primitives()
                uri: str = source['uri']
                cache_name = f"{source_name}.yml"
                source_default_classification[source_name] = source.get('default_classification',
                                                                        classification.UNRESTRICTED)
                try:
                    if uri.endswith('.git'):
                        files = git_clone_repo(source, old_update_time, "*.yml", self.log, UPDATE_DIR)
                        self.log.info(files)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            try:
                                if previous_hashes.get(source_name, {}).get(file, None) != sha256 and val_file(file):
                                    files_sha256[source_name][file] = sha256
                            except UnsupportedFeature as e:
                                self.log.warning(f'{file} | {e}')
                    else:
                        files = url_download(source, old_update_time, self.log, UPDATE_DIR)
                        for file, sha256 in files:
                            files_sha256.setdefault(source_name, {})
                            try:
                                if previous_hashes.get(source_name, {}).get(file, None) != sha256 and val_file(file):
                                    files_sha256[source_name][file] = sha256
                            except UnsupportedFeature as e:
                                self.log.warning(f'{file} | {e}')
                except SkipSource:
                    if cache_name in previous_hashes:
                        files_sha256[cache_name] = previous_hashes[cache_name]
                    continue

            if files_sha256:
                LOGGER.info("Found new Sigma rule files to process!")
                sigma_importer = SigmaImporter(al_client, logger=LOGGER)

                for source, source_val in files_sha256.items():
                    total_imported = 0
                    default_classification = source_default_classification[source]
                    for file in source_val.keys():
                        try:
                            total_imported += sigma_importer.import_file(file, source,
                                                                         default_classification=default_classification)
                        except ValueError:
                            LOGGER.warning(f"{file} failed to import due to a Sigma error")
                        except ComposerError:
                            LOGGER.warning(f"{file} failed to import due to a YAML-parsing error")

                    LOGGER.info(f"{total_imported} signatures were imported for source {source}")

            else:
                LOGGER.info('No new Sigma rule files to process')

        self.set_source_update_time(run_time)
        self.set_source_extra(files_sha256)
        self.set_active_config_hash(self.config_hash(service))
        self.local_update_flag.set()


if __name__ == '__main__':
    with SigmaUpdateServer() as server:
        server.serve_forever()
